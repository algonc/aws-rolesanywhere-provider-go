// Copyright (c) 2025 André Gonçalves
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rolesanywhere

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	randv2 "math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultRefreshMargin is the interval before expiration when credentials are refreshed.
	DefaultRefreshMargin = 5 * time.Minute
	// DefaultRequestTimeout is the timeout applied to each CreateSession HTTP attempt.
	DefaultRequestTimeout = 30 * time.Second
	// DefaultMaxAttempts is the total number of CreateSession attempts.
	DefaultMaxAttempts = 3
	// DefaultRetryBaseDelay is the initial full-jitter backoff limit for transient failures.
	DefaultRetryBaseDelay = 50 * time.Millisecond
	// DefaultThrottleRetryBaseDelay is the initial full-jitter backoff limit for throttling failures.
	DefaultThrottleRetryBaseDelay = time.Second
	// DefaultMaxRetryDelay caps calculated backoff and Retry-After delays.
	DefaultMaxRetryDelay = 20 * time.Second
	// DefaultRefreshFailureDelay is the default delay before retrying a failed early refresh.
	DefaultRefreshFailureDelay = 30 * time.Second
)

var errUnexpectedRedirect = errors.New("unexpected CreateSession redirect")

// APIError describes a non-successful Roles Anywhere CreateSession response.
type APIError struct {
	StatusCode int
	Code       string
	Message    string
	RequestID  string
	Body       string
	RetryAfter time.Duration
}

func (e *APIError) Error() string {
	detail := e.Message
	if detail == "" {
		detail = e.Body
	}
	if detail == "" {
		detail = http.StatusText(e.StatusCode)
	}
	result := fmt.Sprintf("Roles Anywhere CreateSession returned %d", e.StatusCode)
	if e.Code != "" {
		result += " " + e.Code
	}
	if detail != "" {
		result += ": " + detail
	}
	if e.RequestID != "" {
		result += fmt.Sprintf(" (request ID %s)", e.RequestID)
	}
	return result
}

func (e *APIError) HTTPStatusCode() int { return e.StatusCode }
func (e *APIError) ErrorCode() string   { return e.Code }

type errorResponse struct {
	Code       string `json:"code"`
	CodeAlt    string `json:"Code"`
	Type       string `json:"__type"`
	Message    string `json:"message"`
	MessageAlt string `json:"Message"`
}

func newAPIError(resp *http.Response, body []byte, truncated bool, now time.Time) *APIError {
	apiErr := &APIError{
		StatusCode: resp.StatusCode,
		Code:       sanitizeErrorCode(resp.Header.Get("X-Amzn-ErrorType")),
		RequestID:  resp.Header.Get("X-Amzn-RequestId"),
		Body:       strings.TrimSpace(string(body)),
	}
	if truncated {
		apiErr.Body += "... (truncated)"
	}
	var parsed errorResponse
	if json.Unmarshal(body, &parsed) == nil {
		if apiErr.Code == "" {
			apiErr.Code = firstNonEmpty(parsed.Code, parsed.CodeAlt, parsed.Type)
			apiErr.Code = sanitizeErrorCode(apiErr.Code)
		}
		apiErr.Message = firstNonEmpty(parsed.Message, parsed.MessageAlt)
	}
	if delay, ok := parseRetryAfter(resp.Header.Get("Retry-After"), now); ok {
		apiErr.RetryAfter = delay
	}
	return apiErr
}

func sanitizeErrorCode(code string) string {
	if i := strings.IndexByte(code, ':'); i >= 0 {
		code = code[:i]
	}
	if i := strings.LastIndexByte(code, '#'); i >= 0 {
		code = code[i+1:]
	}
	return strings.TrimSpace(code)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func parseRetryAfter(value string, now time.Time) (time.Duration, bool) {
	if value == "" {
		return 0, false
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		if seconds < 0 {
			return 0, false
		}
		return time.Duration(seconds) * time.Second, true
	}
	retryAt, err := http.ParseTime(value)
	if err != nil {
		return 0, false
	}
	if delay := retryAt.Sub(now); delay > 0 {
		return delay, true
	}
	return 0, true
}

// shouldRetry permits retries for transient transport failures, request timeouts,
// throttling, and HTTP 500, 502, 503, and 504 responses.
func (p *Provider) shouldRetry(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return false
	}
	if _, ok := errors.AsType[permanentError](err); ok {
		return false
	}
	if apiErr, ok := errors.AsType[*APIError](err); ok {
		if isRetryableErrorCode(apiErr.Code) {
			return true
		}
		switch apiErr.StatusCode {
		case http.StatusRequestTimeout,
			http.StatusTooManyRequests,
			http.StatusInternalServerError,
			http.StatusBadGateway,
			http.StatusServiceUnavailable,
			http.StatusGatewayTimeout:
			return true
		default:
			return false
		}
	}
	return isRetryableTransportError(err)
}

func isRetryableErrorCode(code string) bool {
	switch code {
	case "RequestTimeout",
		"RequestTimeoutException",
		"Throttling",
		"ThrottlingException",
		"ThrottledException",
		"RequestThrottledException",
		"TooManyRequestsException",
		"RequestLimitExceeded",
		"RequestThrottled",
		"SlowDown",
		"PriorRequestNotComplete":
		return true
	default:
		return false
	}
}

func isThrottleError(err error) bool {
	apiErr, ok := errors.AsType[*APIError](err)
	if !ok {
		return false
	}
	if apiErr.StatusCode == http.StatusTooManyRequests {
		return true
	}
	return strings.Contains(strings.ToLower(apiErr.Code), "throttl") || apiErr.Code == "SlowDown"
}

func isRetryableTransportError(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, errUnexpectedRedirect) {
		return false
	}
	if _, ok := errors.AsType[x509.UnknownAuthorityError](err); ok {
		return false
	}
	if _, ok := errors.AsType[x509.HostnameError](err); ok {
		return false
	}
	if _, ok := errors.AsType[x509.CertificateInvalidError](err); ok {
		return false
	}
	if _, ok := errors.AsType[*tls.CertificateVerificationError](err); ok {
		return false
	}
	if _, ok := errors.AsType[tls.RecordHeaderError](err); ok {
		return false
	}

	if dnsError, ok := errors.AsType[*net.DNSError](err); ok {
		return !dnsError.IsNotFound
	}
	if urlError, ok := errors.AsType[*url.Error](err); ok {
		if strings.Contains(urlError.Error(), "unsupported protocol scheme") ||
			strings.Contains(urlError.Error(), "invalid header") {
			return false
		}
		return isRetryableTransportError(urlError.Err)
	}
	return true
}

// retryDelay applies exponential backoff with full jitter and honors Retry-After.
func (p *Provider) retryDelay(retry int, err error) time.Duration {
	base := p.retryBaseDelay
	if isThrottleError(err) {
		base = p.throttleRetryBaseDelay
	}
	delay := base
	for i := 0; i < retry && delay < p.maxRetryDelay; i++ {
		if delay > p.maxRetryDelay/2 {
			delay = p.maxRetryDelay
			break
		}
		delay *= 2
	}
	if delay > p.maxRetryDelay {
		delay = p.maxRetryDelay
	}

	if apiErr, ok := errors.AsType[*APIError](err); ok && apiErr.RetryAfter > 0 {
		return min(apiErr.RetryAfter, p.maxRetryDelay)
	}

	random := randv2.Float64
	if p.randFloat64 != nil {
		random = p.randFloat64
	}
	return time.Duration(random() * float64(delay))
}

func (p *Provider) sleepForRetry(ctx context.Context, delay time.Duration) error {
	if p.sleep != nil {
		return p.sleep(ctx, delay)
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func rejectRedirect(req *http.Request, _ []*http.Request) error {
	return fmt.Errorf("%w to %s", errUnexpectedRedirect, req.URL.Redacted())
}

type permanentError struct{ err error }

func (e permanentError) Error() string { return e.err.Error() }
func (e permanentError) Unwrap() error { return e.err }

func permanent(err error) error { return permanentError{err: err} }
