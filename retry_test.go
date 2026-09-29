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
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"
)

type retryRoundTripper func(*http.Request) (*http.Response, error)

func (fn retryRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

type trackingBody struct {
	io.Reader
	closed atomic.Bool
}

func (b *trackingBody) Close() error {
	b.closed.Store(true)
	return nil
}

func newRetryTestProvider(t *testing.T, now *time.Time, transport http.RoundTripper, opts ...Option) *Provider {
	t.Helper()
	keyPEM, certPEM := mustKeyAndCert(t)
	options := []Option{
		WithPrivateKeyPath("key.pem"),
		WithCertificatePath("cert.pem"),
		WithHTTPClient(&http.Client{Transport: transport}),
	}
	options = append(options, opts...)
	p := NewProvider(options...)
	p.host = "rolesanywhere.test"
	p.endpoint = "https://rolesanywhere.test/sessions"
	p.now = func() time.Time { return *now }
	p.readFile = func(path string) ([]byte, error) {
		if path == "key.pem" {
			return keyPEM, nil
		}
		return certPEM, nil
	}
	p.sleep = func(context.Context, time.Duration) error { return nil }
	p.randFloat64 = func() float64 { return 0.5 }
	return p
}

func successHTTPResponse(req *http.Request, expiration time.Time) *http.Response {
	body := fmt.Sprintf(
		`{"credentialSet":[{"credentials":{"accessKeyId":"AKIA_TEST","secretAccessKey":"SECRET","sessionToken":"TOKEN","expiration":%q}}]}`,
		expiration.Format(time.RFC3339),
	)
	return &http.Response{
		StatusCode: http.StatusCreated,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
}

func errorHTTPResponse(req *http.Request, status int, code, message string) *http.Response {
	body, _ := json.Marshal(map[string]string{"code": code, "message": message})
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(string(body))),
		Request:    req,
	}
}

func TestProvider_RetryPolicy(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		code        string
		wantCalls   int
		wantSuccess bool
	}{
		{"request_timeout", http.StatusRequestTimeout, "", 2, true},
		{"too_many_requests", http.StatusTooManyRequests, "", 2, true},
		{"internal_server_error", http.StatusInternalServerError, "", 2, true},
		{"bad_gateway", http.StatusBadGateway, "", 2, true},
		{"service_unavailable", http.StatusServiceUnavailable, "", 2, true},
		{"gateway_timeout", http.StatusGatewayTimeout, "", 2, true},
		{"throttling_as_bad_request", http.StatusBadRequest, "ThrottlingException", 2, true},
		{"request_timeout_as_bad_request", http.StatusBadRequest, "RequestTimeoutException", 2, true},
		{"validation", http.StatusBadRequest, "ValidationException", 1, false},
		{"unauthorized", http.StatusUnauthorized, "NotAuthorized", 1, false},
		{"forbidden", http.StatusForbidden, "AccessDeniedException", 1, false},
		{"not_found", http.StatusNotFound, "ResourceNotFoundException", 1, false},
		{"not_implemented", http.StatusNotImplemented, "", 1, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
			calls := 0
			transport := retryRoundTripper(func(req *http.Request) (*http.Response, error) {
				calls++
				if calls == 1 {
					return errorHTTPResponse(req, tt.status, tt.code, "failed"), nil
				}
				return successHTTPResponse(req, now.Add(time.Hour)), nil
			})
			provider := newRetryTestProvider(t, &now, transport)

			creds, err := provider.Retrieve(context.Background())
			if tt.wantSuccess && err != nil {
				t.Fatalf("Retrieve: %v", err)
			}
			if !tt.wantSuccess && err == nil {
				t.Fatal("Retrieve succeeded, want an error")
			}
			if tt.wantSuccess && creds.AccessKeyID != "AKIA_TEST" {
				t.Fatalf("AccessKeyID = %q, want AKIA_TEST", creds.AccessKeyID)
			}
			if calls != tt.wantCalls {
				t.Fatalf("calls = %d, want %d", calls, tt.wantCalls)
			}
		})
	}
}

func TestProvider_RetriesExhausted(t *testing.T) {
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	calls := 0
	provider := newRetryTestProvider(t, &now, retryRoundTripper(func(req *http.Request) (*http.Response, error) {
		calls++
		resp := errorHTTPResponse(req, http.StatusServiceUnavailable, "ServiceUnavailable", "try later")
		resp.Header.Set("X-Amzn-RequestId", "request-123")
		return resp, nil
	}), WithMaxAttempts(3))

	_, err := provider.Retrieve(context.Background())
	if err == nil {
		t.Fatal("Retrieve succeeded, want an error")
	}
	if calls != 3 {
		t.Fatalf("calls = %d, want 3", calls)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error type = %T, want *APIError", err)
	}
	if apiErr.StatusCode != http.StatusServiceUnavailable || apiErr.Code != "ServiceUnavailable" {
		t.Fatalf("API error = %+v", apiErr)
	}
	if apiErr.RequestID != "request-123" || !strings.Contains(err.Error(), "request-123") {
		t.Fatalf("error does not contain request ID: %v", err)
	}
}

func TestProvider_TransportRetryPolicy(t *testing.T) {
	tests := []struct {
		name           string
		transportError error
		wantCalls      int
		wantSuccess    bool
	}{
		{"connection_reset", errors.New("connection reset by peer"), 2, true},
		{"nxdomain", &url.Error{Op: "Post", URL: "https://rolesanywhere.test", Err: &net.DNSError{Err: "no such host", IsNotFound: true}}, 1, false},
		{"unknown_authority", &url.Error{Op: "Post", URL: "https://rolesanywhere.test", Err: x509.UnknownAuthorityError{}}, 1, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
			calls := 0
			provider := newRetryTestProvider(t, &now, retryRoundTripper(func(req *http.Request) (*http.Response, error) {
				calls++
				if calls == 1 {
					return nil, tt.transportError
				}
				return successHTTPResponse(req, now.Add(time.Hour)), nil
			}))

			_, err := provider.Retrieve(context.Background())
			if tt.wantSuccess && err != nil {
				t.Fatalf("Retrieve: %v", err)
			}
			if !tt.wantSuccess && err == nil {
				t.Fatal("Retrieve succeeded, want an error")
			}
			if calls != tt.wantCalls {
				t.Fatalf("calls = %d, want %d", calls, tt.wantCalls)
			}
		})
	}
}

func TestProvider_RequestTimeoutIsRetried(t *testing.T) {
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	calls := 0
	provider := newRetryTestProvider(t, &now, retryRoundTripper(func(req *http.Request) (*http.Response, error) {
		calls++
		<-req.Context().Done()
		return nil, req.Context().Err()
	}), WithRequestTimeout(5*time.Millisecond))

	_, err := provider.Retrieve(context.Background())
	if err == nil {
		t.Fatal("Retrieve succeeded, want an error")
	}
	if calls != DefaultMaxAttempts {
		t.Fatalf("calls = %d, want %d", calls, DefaultMaxAttempts)
	}
}

func TestProvider_CancellationStopsBackoff(t *testing.T) {
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	calls := 0
	provider := newRetryTestProvider(t, &now, retryRoundTripper(func(req *http.Request) (*http.Response, error) {
		calls++
		return errorHTTPResponse(req, http.StatusServiceUnavailable, "ServiceUnavailable", "try later"), nil
	}))
	ctx, cancel := context.WithCancel(context.Background())
	provider.sleep = func(ctx context.Context, _ time.Duration) error {
		cancel()
		return ctx.Err()
	}

	_, err := provider.Retrieve(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %v, want *APIError in chain", err)
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1", calls)
	}
}

func TestProvider_RetryRebuildsSignedRequest(t *testing.T) {
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	var dates, authorizations, bodies []string
	provider := newRetryTestProvider(t, &now, retryRoundTripper(func(req *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		dates = append(dates, req.Header.Get("X-Amz-Date"))
		authorizations = append(authorizations, req.Header.Get("Authorization"))
		bodies = append(bodies, string(body))
		if len(dates) == 1 {
			now = now.Add(time.Minute)
			return errorHTTPResponse(req, http.StatusServiceUnavailable, "ServiceUnavailable", "try later"), nil
		}
		return successHTTPResponse(req, now.Add(time.Hour)), nil
	}))
	provider.SessionName = "workload-session"

	if _, err := provider.Retrieve(context.Background()); err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if len(dates) != 2 || dates[0] == dates[1] {
		t.Fatalf("signing dates = %v, want two different values", dates)
	}
	if authorizations[0] == authorizations[1] {
		t.Fatal("Authorization header was not regenerated")
	}
	if bodies[0] != bodies[1] {
		t.Fatalf("request bodies differ: %q != %q", bodies[0], bodies[1])
	}
	if !strings.Contains(bodies[0], `"roleSessionName":"workload-session"`) || strings.Contains(bodies[0], `"sessionName"`) {
		t.Fatalf("unexpected session name field: %s", bodies[0])
	}
}

func TestProvider_RetryDelay(t *testing.T) {
	provider := NewProvider()
	provider.randFloat64 = func() float64 { return 0.5 }

	if got := provider.retryDelay(0, errors.New("temporary")); got != DefaultRetryBaseDelay/2 {
		t.Fatalf("transient delay = %s, want %s", got, DefaultRetryBaseDelay/2)
	}
	throttled := &APIError{StatusCode: http.StatusBadRequest, Code: "ThrottlingException"}
	if got := provider.retryDelay(0, throttled); got != DefaultThrottleRetryBaseDelay/2 {
		t.Fatalf("throttle delay = %s, want %s", got, DefaultThrottleRetryBaseDelay/2)
	}
	withRetryAfter := &APIError{StatusCode: http.StatusServiceUnavailable, RetryAfter: time.Minute}
	if got := provider.retryDelay(0, withRetryAfter); got != DefaultMaxRetryDelay {
		t.Fatalf("Retry-After delay = %s, want %s", got, DefaultMaxRetryDelay)
	}
}

func TestProvider_RetryOptions(t *testing.T) {
	provider := NewProvider(
		WithRequestTimeout(4*time.Second),
		WithMaxAttempts(5),
		WithRetryBaseDelay(10*time.Millisecond),
		WithThrottleRetryBaseDelay(2*time.Second),
		WithMaxRetryDelay(9*time.Second),
		WithRefreshFailureDelay(time.Minute),
	)
	if provider.requestTimeout != 4*time.Second ||
		provider.maxAttempts != 5 ||
		provider.retryBaseDelay != 10*time.Millisecond ||
		provider.throttleRetryBaseDelay != 2*time.Second ||
		provider.maxRetryDelay != 9*time.Second ||
		provider.refreshFailureDelay != time.Minute {
		t.Fatalf("unexpected retry options: %+v", provider)
	}
	if got := NewProvider(WithMaxAttempts(0)).maxAttempts; got != 1 {
		t.Fatalf("MaxAttempts = %d, want 1", got)
	}
}

func TestProvider_HonorsRetryAfter(t *testing.T) {
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	calls := 0
	var delays []time.Duration
	provider := newRetryTestProvider(t, &now, retryRoundTripper(func(req *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			resp := errorHTTPResponse(req, http.StatusServiceUnavailable, "ServiceUnavailable", "try later")
			resp.Header.Set("Retry-After", "60")
			return resp, nil
		}
		return successHTTPResponse(req, now.Add(time.Hour)), nil
	}))
	provider.sleep = func(_ context.Context, delay time.Duration) error {
		delays = append(delays, delay)
		return nil
	}

	if _, err := provider.Retrieve(context.Background()); err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if len(delays) != 1 || delays[0] != DefaultMaxRetryDelay {
		t.Fatalf("delays = %v, want [%s]", delays, DefaultMaxRetryDelay)
	}
}

func TestProvider_ConcurrentRetrieveFetchesOnce(t *testing.T) {
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	provider := newRetryTestProvider(t, &now, retryRoundTripper(func(req *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return successHTTPResponse(req, now.Add(time.Hour)), nil
	}))

	const goroutines = 10
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := provider.Retrieve(context.Background())
			errs <- err
		}()
	}
	<-started
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("Retrieve: %v", err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("calls = %d, want 1", got)
	}
}

func TestProvider_ConcurrentWaiterCanCancel(t *testing.T) {
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	started := make(chan struct{})
	release := make(chan struct{})
	provider := newRetryTestProvider(t, &now, retryRoundTripper(func(req *http.Request) (*http.Response, error) {
		close(started)
		<-release
		return successHTTPResponse(req, now.Add(time.Hour)), nil
	}))
	leaderDone := make(chan error, 1)
	go func() {
		_, err := provider.Retrieve(context.Background())
		leaderDone <- err
	}()
	<-started

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := provider.Retrieve(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiter error = %v, want context.DeadlineExceeded", err)
	}
	close(release)
	if err := <-leaderDone; err != nil {
		t.Fatalf("leader Retrieve: %v", err)
	}
}

func TestProvider_UsesValidCredentialsAfterRefreshFailure(t *testing.T) {
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	calls := 0
	provider := newRetryTestProvider(t, &now, retryRoundTripper(func(req *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return successHTTPResponse(req, now.Add(10*time.Minute)), nil
		}
		return errorHTTPResponse(req, http.StatusServiceUnavailable, "ServiceUnavailable", "try later"), nil
	}))

	first, err := provider.Retrieve(context.Background())
	if err != nil {
		t.Fatalf("initial Retrieve: %v", err)
	}
	now = now.Add(6 * time.Minute)
	second, err := provider.Retrieve(context.Background())
	if err != nil {
		t.Fatalf("refresh Retrieve: %v", err)
	}
	if second.AccessKeyID != first.AccessKeyID {
		t.Fatalf("fallback credentials = %q, want %q", second.AccessKeyID, first.AccessKeyID)
	}
	if calls != 1+DefaultMaxAttempts {
		t.Fatalf("calls = %d, want %d", calls, 1+DefaultMaxAttempts)
	}
	if _, err := provider.Retrieve(context.Background()); err != nil {
		t.Fatalf("Retrieve during refresh cooldown: %v", err)
	}
	if calls != 1+DefaultMaxAttempts {
		t.Fatalf("cooldown caused another refresh; calls = %d", calls)
	}
}

func TestProvider_DoesNotUseExpiredCredentialsAfterRefreshFailure(t *testing.T) {
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	calls := 0
	provider := newRetryTestProvider(t, &now, retryRoundTripper(func(req *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return successHTTPResponse(req, now.Add(time.Minute)), nil
		}
		return errorHTTPResponse(req, http.StatusServiceUnavailable, "ServiceUnavailable", "try later"), nil
	}))

	if _, err := provider.Retrieve(context.Background()); err != nil {
		t.Fatalf("initial Retrieve: %v", err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := provider.Retrieve(context.Background()); err == nil {
		t.Fatal("Retrieve succeeded with expired cached credentials")
	}
}

func TestProvider_ResponseReadFailureIsRetried(t *testing.T) {
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	calls := 0
	readErr := errors.New("response interrupted")
	provider := newRetryTestProvider(t, &now, retryRoundTripper(func(req *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return &http.Response{
				StatusCode: http.StatusCreated,
				Header:     make(http.Header),
				Body:       io.NopCloser(iotest.ErrReader(readErr)),
				Request:    req,
			}, nil
		}
		return successHTTPResponse(req, now.Add(time.Hour)), nil
	}))

	if _, err := provider.Retrieve(context.Background()); err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want 2", calls)
	}
}

func TestProvider_ResponseBodiesAreClosed(t *testing.T) {
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	firstBody := &trackingBody{Reader: strings.NewReader(`{"message":"try later"}`)}
	success := successHTTPResponse(nil, now.Add(time.Hour))
	secondBody := &trackingBody{Reader: success.Body}
	calls := 0
	provider := newRetryTestProvider(t, &now, retryRoundTripper(func(req *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return &http.Response{
				StatusCode: http.StatusServiceUnavailable,
				Header:     make(http.Header),
				Body:       firstBody,
				Request:    req,
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusCreated,
			Header:     make(http.Header),
			Body:       secondBody,
			Request:    req,
		}, nil
	}))

	if _, err := provider.Retrieve(context.Background()); err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if !firstBody.closed.Load() || !secondBody.closed.Load() {
		t.Fatalf("closed bodies = first:%t second:%t", firstBody.closed.Load(), secondBody.closed.Load())
	}
}

func TestProvider_MalformedSuccessIsNotRetried(t *testing.T) {
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	calls := 0
	provider := newRetryTestProvider(t, &now, retryRoundTripper(func(req *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{
			StatusCode: http.StatusCreated,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`not-json`)),
			Request:    req,
		}, nil
	}))

	if _, err := provider.Retrieve(context.Background()); err == nil {
		t.Fatal("Retrieve succeeded, want a parsing error")
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1", calls)
	}
}

func TestProvider_InvalidCredentialResponses(t *testing.T) {
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	provider := NewProvider()
	provider.now = func() time.Time { return now }
	tests := []struct {
		name string
		body string
		want string
	}{
		{"empty", `{}`, "no credentialSet"},
		{"missing_access_key", `{"credentialSet":[{"credentials":{"secretAccessKey":"S","sessionToken":"T","expiration":"2099-01-01T00:00:00Z"}}]}`, "no access key ID"},
		{"missing_secret", `{"credentialSet":[{"credentials":{"accessKeyId":"A","sessionToken":"T","expiration":"2099-01-01T00:00:00Z"}}]}`, "no secret access key"},
		{"missing_token", `{"credentialSet":[{"credentials":{"accessKeyId":"A","secretAccessKey":"S","expiration":"2099-01-01T00:00:00Z"}}]}`, "no session token"},
		{"invalid_expiration", `{"credentialSet":[{"credentials":{"accessKeyId":"A","secretAccessKey":"S","sessionToken":"T","expiration":"invalid"}}]}`, "parsing credential expiration"},
		{"expired", `{"credentialSet":[{"credentials":{"accessKeyId":"A","secretAccessKey":"S","sessionToken":"T","expiration":"2020-01-01T00:00:00Z"}}]}`, "returned expired credentials"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := provider.parseSessionCredentials([]byte(tt.body))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestProvider_ErrorBodyIsBounded(t *testing.T) {
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	provider := newRetryTestProvider(t, &now, retryRoundTripper(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusBadRequest,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(strings.Repeat("x", maxErrorBodyBytes+100))),
			Request:    req,
		}, nil
	}))

	_, err := provider.Retrieve(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %v, want *APIError", err)
	}
	if len(apiErr.Body) != maxErrorBodyBytes+len("... (truncated)") {
		t.Fatalf("error body length = %d", len(apiErr.Body))
	}
}

func TestProvider_RejectsRedirects(t *testing.T) {
	var targetCalls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetCalls.Add(1)
	}))
	defer target.Close()
	var sourceCalls atomic.Int32
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		sourceCalls.Add(1)
		http.Redirect(w, req, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	keyPEM, certPEM := mustKeyAndCert(t)
	provider := NewProvider(
		WithPrivateKeyPath("key.pem"),
		WithCertificatePath("cert.pem"),
		WithHTTPClient(source.Client()),
	)
	provider.host = "rolesanywhere.test"
	provider.endpoint = source.URL + "/sessions"
	provider.now = func() time.Time { return now }
	provider.readFile = func(path string) ([]byte, error) {
		if path == "key.pem" {
			return keyPEM, nil
		}
		return certPEM, nil
	}
	provider.sleep = func(context.Context, time.Duration) error { return nil }

	if _, err := provider.Retrieve(context.Background()); !errors.Is(err, errUnexpectedRedirect) {
		t.Fatalf("error = %v, want redirect rejection", err)
	}
	if sourceCalls.Load() != 1 || targetCalls.Load() != 0 {
		t.Fatalf("source calls = %d, target calls = %d", sourceCalls.Load(), targetCalls.Load())
	}
}
