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
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	maxSuccessBodyBytes = 1 << 20
	maxErrorBodyBytes   = 2048
)

type preparedSessionRequest struct {
	privateKey     crypto.PrivateKey
	algorithm      string
	certificate    *x509.Certificate
	certificate64  string
	payload        []byte
	host           string
	endpoint       string
	canonicalURI   string
	canonicalQuery string
}

type createSessionRequestBody struct {
	DurationSeconds int64  `json:"durationSeconds"`
	ProfileARN      string `json:"profileArn"`
	RoleARN         string `json:"roleArn"`
	RoleSessionName string `json:"roleSessionName,omitempty"`
	TrustAnchorARN  string `json:"trustAnchorArn"`
}

// createSessionAndGetCredentials signs every attempt independently and retries
// only failures accepted by shouldRetry. The context controls the full operation.
func (p *Provider) createSessionAndGetCredentials(ctx context.Context) (sessionCredentials, error) {
	prepared, err := p.prepareSessionRequest()
	if err != nil {
		return sessionCredentials{}, err
	}

	var lastErr error
	for attempt := 0; attempt < p.maxAttempts; attempt++ {
		body, err := p.attemptCreateSession(ctx, prepared)
		if err == nil {
			return p.parseSessionCredentials(body)
		}
		lastErr = err
		if attempt+1 >= p.maxAttempts || !p.shouldRetry(ctx, err) {
			return sessionCredentials{}, fmt.Errorf("CreateSession failed after %d attempt(s): %w", attempt+1, err)
		}

		delay := p.retryDelay(attempt, err)
		if err := p.sleepForRetry(ctx, delay); err != nil {
			return sessionCredentials{}, fmt.Errorf("CreateSession retries stopped: %w", errors.Join(lastErr, err))
		}
	}
	return sessionCredentials{}, fmt.Errorf("CreateSession failed: %w", lastErr)
}

func (p *Provider) prepareSessionRequest() (preparedSessionRequest, error) {
	keyPEM, err := p.readFile(p.PrivateKeyPath)
	if err != nil {
		return preparedSessionRequest{}, fmt.Errorf("reading private key: %w", err)
	}
	privateKey, err := parsePrivateKey(keyPEM)
	if err != nil {
		return preparedSessionRequest{}, fmt.Errorf("parsing private key: %w", err)
	}
	algorithm, err := signingAlgorithmForPrivateKey(privateKey)
	if err != nil {
		return preparedSessionRequest{}, err
	}

	certificatePEM, err := p.readFile(p.CertificatePath)
	if err != nil {
		return preparedSessionRequest{}, fmt.Errorf("reading certificate: %w", err)
	}
	certificate, err := parseCertificate(certificatePEM)
	if err != nil {
		return preparedSessionRequest{}, fmt.Errorf("parsing certificate: %w", err)
	}
	if err := validatePrivateKeyMatchesCertificate(privateKey, certificate); err != nil {
		return preparedSessionRequest{}, fmt.Errorf("validating private key and certificate: %w", err)
	}

	payload, err := json.Marshal(createSessionRequestBody{
		DurationSeconds: p.DurationSeconds,
		ProfileARN:      p.ProfileArn,
		RoleARN:         p.RoleArn,
		RoleSessionName: p.SessionName,
		TrustAnchorARN:  p.TrustAnchorArn,
	})
	if err != nil {
		return preparedSessionRequest{}, fmt.Errorf("marshalling CreateSession payload: %w", err)
	}

	host := p.host
	if host == "" {
		host = fmt.Sprintf("rolesanywhere.%s.amazonaws.com", p.Region)
	}
	endpoint := p.endpoint
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://%s/sessions", host)
	}
	parsedEndpoint, err := url.Parse(endpoint)
	if err != nil {
		return preparedSessionRequest{}, fmt.Errorf("parsing CreateSession endpoint: %w", err)
	}
	if parsedEndpoint.Scheme == "" || parsedEndpoint.Host == "" {
		return preparedSessionRequest{}, fmt.Errorf("invalid CreateSession endpoint %q", endpoint)
	}
	canonicalURI := parsedEndpoint.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}

	return preparedSessionRequest{
		privateKey:     privateKey,
		algorithm:      algorithm,
		certificate:    certificate,
		certificate64:  base64.StdEncoding.EncodeToString(certificate.Raw),
		payload:        payload,
		host:           host,
		endpoint:       endpoint,
		canonicalURI:   canonicalURI,
		canonicalQuery: parsedEndpoint.Query().Encode(),
	}, nil
}

func (p *Provider) attemptCreateSession(ctx context.Context, prepared preparedSessionRequest) ([]byte, error) {
	attemptCtx, cancel := context.WithTimeout(ctx, p.requestTimeout)
	defer cancel()

	req, err := p.signedRequest(attemptCtx, prepared)
	if err != nil {
		return nil, permanent(fmt.Errorf("creating signed CreateSession request: %w", err))
	}
	resp, err := p.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("calling CreateSession: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	limit := int64(maxErrorBodyBytes)
	if resp.StatusCode == http.StatusCreated {
		limit = maxSuccessBodyBytes
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	truncated := int64(len(body)) > limit
	if truncated {
		body = body[:limit]
	}
	if resp.StatusCode != http.StatusCreated {
		return nil, newAPIError(resp, body, truncated, p.now().UTC())
	}
	if readErr != nil {
		return nil, fmt.Errorf("reading CreateSession response: %w", readErr)
	}
	if truncated {
		return nil, permanent(fmt.Errorf("CreateSession response exceeds %d bytes", maxSuccessBodyBytes))
	}
	return body, nil
}

func (p *Provider) signedRequest(ctx context.Context, prepared preparedSessionRequest) (*http.Request, error) {
	now := p.now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")
	const contentType = "application/json"
	const signedHeaders = "content-type;host;x-amz-date;x-amz-x509"

	canonicalHeaders := strings.Join([]string{
		"content-type:" + contentType,
		"host:" + prepared.host,
		"x-amz-date:" + amzDate,
		"x-amz-x509:" + prepared.certificate64,
	}, "\n") + "\n"
	canonicalRequest := strings.Join([]string{
		http.MethodPost,
		prepared.canonicalURI,
		prepared.canonicalQuery,
		canonicalHeaders,
		signedHeaders,
		sha256Hex(prepared.payload),
	}, "\n")
	credentialScope := fmt.Sprintf("%s/%s/rolesanywhere/aws4_request", dateStamp, p.Region)
	stringToSign := strings.Join([]string{
		prepared.algorithm,
		amzDate,
		credentialScope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")
	signature, err := signString(prepared.privateKey, stringToSign)
	if err != nil {
		return nil, fmt.Errorf("signing request: %w", err)
	}
	authorization := fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		prepared.algorithm,
		prepared.certificate.SerialNumber.String(),
		credentialScope,
		signedHeaders,
		hex.EncodeToString(signature),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, prepared.endpoint, bytes.NewReader(prepared.payload))
	if err != nil {
		return nil, err
	}
	req.Host = prepared.host
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", authorization)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-X509", prepared.certificate64)
	return req, nil
}

func (p *Provider) parseSessionCredentials(body []byte) (sessionCredentials, error) {
	var parsed createSessionResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return sessionCredentials{}, fmt.Errorf("parsing CreateSession response: %w", err)
	}
	if len(parsed.CredentialSet) == 0 {
		return sessionCredentials{}, fmt.Errorf("CreateSession response contains no credentialSet")
	}

	credentials := parsed.CredentialSet[0].Credentials
	switch {
	case credentials.AccessKeyID == "":
		return sessionCredentials{}, fmt.Errorf("CreateSession response contains no access key ID")
	case credentials.SecretAccessKey == "":
		return sessionCredentials{}, fmt.Errorf("CreateSession response contains no secret access key")
	case credentials.SessionToken == "":
		return sessionCredentials{}, fmt.Errorf("CreateSession response contains no session token")
	}
	expiration, err := time.Parse(time.RFC3339, credentials.Expiration)
	if err != nil {
		expiration, err = time.Parse("2006-01-02T15:04:05", credentials.Expiration)
		if err != nil {
			return sessionCredentials{}, fmt.Errorf("parsing credential expiration %q: %w", credentials.Expiration, err)
		}
	}
	if !p.now().UTC().Before(expiration) {
		return sessionCredentials{}, fmt.Errorf("CreateSession returned expired credentials")
	}

	return sessionCredentials{
		AccessKeyID:     credentials.AccessKeyID,
		SecretAccessKey: credentials.SecretAccessKey,
		SessionToken:    credentials.SessionToken,
		Expiration:      expiration,
	}, nil
}

// client rejects redirects unless the configured client supplies a redirect policy.
func (p *Provider) client() *http.Client {
	client := p.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	clientCopy := *client
	if clientCopy.CheckRedirect == nil {
		clientCopy.CheckRedirect = rejectRedirect
	}
	return &clientCopy
}
