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
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// Provider implements aws.CredentialsProvider and obtains temporary credentials
// from AWS RolesAnywhere by performing the SigV4-X509 signing flow and calling CreateSession.
type Provider struct {
	PrivateKeyPath  string
	CertificatePath string
	Region          string
	DurationSeconds int64
	ProfileArn      string
	RoleArn         string
	TrustAnchorArn  string
	SessionName     string

	// Optional HTTP client (useful for tests)
	HTTPClient *http.Client

	// caching
	mu                 sync.Mutex
	refresh            *refreshCall
	cachedCreds        aws.Credentials
	expiration         time.Time
	cachedLifetime     time.Duration
	nextRefreshAttempt time.Time
	refreshMargin      time.Duration

	requestTimeout         time.Duration
	maxAttempts            int
	retryBaseDelay         time.Duration
	throttleRetryBaseDelay time.Duration
	maxRetryDelay          time.Duration
	refreshFailureDelay    time.Duration

	// test hooks
	host        string
	endpoint    string
	now         func() time.Time
	readFile    func(string) ([]byte, error)
	sleep       func(context.Context, time.Duration) error
	randFloat64 func() float64
}

type refreshCall struct {
	done  chan struct{}
	creds aws.Credentials
	err   error
}

// NewProvider constructs a new Provider with sensible defaults.
func NewProvider(opts ...Option) *Provider {
	p := &Provider{
		Region:                 "us-east-1",
		DurationSeconds:        3600,
		refreshMargin:          DefaultRefreshMargin,
		HTTPClient:             http.DefaultClient,
		requestTimeout:         DefaultRequestTimeout,
		maxAttempts:            DefaultMaxAttempts,
		retryBaseDelay:         DefaultRetryBaseDelay,
		throttleRetryBaseDelay: DefaultThrottleRetryBaseDelay,
		maxRetryDelay:          DefaultMaxRetryDelay,
		refreshFailureDelay:    DefaultRefreshFailureDelay,
		now:                    time.Now,
		readFile:               os.ReadFile,
	}
	for _, o := range opts {
		o(p)
	}
	if p.refreshMargin < 0 {
		p.refreshMargin = 0
	}
	if p.requestTimeout <= 0 {
		p.requestTimeout = DefaultRequestTimeout
	}
	if p.maxAttempts < 1 {
		p.maxAttempts = 1
	}
	if p.retryBaseDelay <= 0 {
		p.retryBaseDelay = DefaultRetryBaseDelay
	}
	if p.throttleRetryBaseDelay <= 0 {
		p.throttleRetryBaseDelay = DefaultThrottleRetryBaseDelay
	}
	if p.maxRetryDelay <= 0 {
		p.maxRetryDelay = DefaultMaxRetryDelay
	}
	if p.refreshFailureDelay <= 0 {
		p.refreshFailureDelay = DefaultRefreshFailureDelay
	}
	return p
}

// Option configures Provider
type Option func(*Provider)

func WithPrivateKeyPath(path string) Option {
	return func(p *Provider) { p.PrivateKeyPath = path }
}
func WithCertificatePath(path string) Option {
	return func(p *Provider) { p.CertificatePath = path }
}
func WithRegion(region string) Option {
	return func(p *Provider) { p.Region = region }
}
func WithDurationSeconds(sec int64) Option {
	return func(p *Provider) { p.DurationSeconds = sec }
}
func WithProfileArn(a string) Option {
	return func(p *Provider) { p.ProfileArn = a }
}
func WithRoleArn(a string) Option {
	return func(p *Provider) { p.RoleArn = a }
}
func WithTrustAnchorArn(a string) Option {
	return func(p *Provider) { p.TrustAnchorArn = a }
}
func WithSessionName(a string) Option {
	return func(p *Provider) { p.SessionName = a }
}
func WithHTTPClient(c *http.Client) Option {
	return func(p *Provider) { p.HTTPClient = c }
}
func WithRefreshMargin(d time.Duration) Option {
	return func(p *Provider) { p.refreshMargin = d }
}

// WithRequestTimeout sets the timeout for each CreateSession HTTP attempt.
func WithRequestTimeout(d time.Duration) Option {
	return func(p *Provider) { p.requestTimeout = d }
}

// WithMaxAttempts sets the total number of CreateSession attempts. Set it to 1 to disable retries.
func WithMaxAttempts(n int) Option {
	return func(p *Provider) { p.maxAttempts = n }
}

// WithRetryBaseDelay sets the initial backoff limit for transient failures.
func WithRetryBaseDelay(d time.Duration) Option {
	return func(p *Provider) { p.retryBaseDelay = d }
}

// WithThrottleRetryBaseDelay sets the initial backoff limit for throttling failures.
func WithThrottleRetryBaseDelay(d time.Duration) Option {
	return func(p *Provider) { p.throttleRetryBaseDelay = d }
}

// WithMaxRetryDelay caps retry backoff and Retry-After delays.
func WithMaxRetryDelay(d time.Duration) Option {
	return func(p *Provider) { p.maxRetryDelay = d }
}

// WithRefreshFailureDelay sets how long valid cached credentials suppress another refresh after a failure.
func WithRefreshFailureDelay(d time.Duration) Option {
	return func(p *Provider) { p.refreshFailureDelay = d }
}

// Retrieve returns cached credentials or obtains a new Roles Anywhere session.
// Concurrent refreshes share one request. A failed early refresh returns cached
// credentials while they remain valid and delays the next refresh attempt.
func (p *Provider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	now := p.now().UTC()
	if creds, ok := p.cachedCredentials(now); ok {
		return creds, nil
	}

	p.mu.Lock()
	if creds, ok := p.cachedCredentialsLocked(p.now().UTC()); ok {
		p.mu.Unlock()
		return creds, nil
	}
	if call := p.refresh; call != nil {
		p.mu.Unlock()
		select {
		case <-call.done:
			return call.creds, call.err
		case <-ctx.Done():
			if creds, ok := p.validCachedCredentials(p.now().UTC()); ok {
				return creds, nil
			}
			return aws.Credentials{}, ctx.Err()
		}
	}
	if err := ctx.Err(); err != nil {
		if p.hasValidCachedCredentials(now) {
			creds := p.cachedCreds
			p.mu.Unlock()
			return creds, nil
		}
		p.mu.Unlock()
		return aws.Credentials{}, err
	}
	call := &refreshCall{done: make(chan struct{})}
	p.refresh = call
	p.mu.Unlock()

	call.creds, call.err = p.refreshCredentials(ctx)
	p.mu.Lock()
	p.refresh = nil
	close(call.done)
	p.mu.Unlock()
	return call.creds, call.err
}

func (p *Provider) refreshCredentials(ctx context.Context) (aws.Credentials, error) {
	creds, err := p.createSessionAndGetCredentials(ctx)
	if err != nil {
		if cached, ok := p.useCachedCredentialsAfterFailure(p.now().UTC()); ok {
			return cached, nil
		}
		return aws.Credentials{}, err
	}

	awsCreds := aws.Credentials{
		AccessKeyID:     creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
		SessionToken:    creds.SessionToken,
		Source:          "RolesAnywhereProvider",
		CanExpire:       true,
		Expires:         creds.Expiration,
	}
	p.mu.Lock()
	p.cachedCreds = awsCreds
	p.expiration = creds.Expiration
	p.cachedLifetime = creds.Expiration.Sub(p.now().UTC())
	p.nextRefreshAttempt = time.Time{}
	p.mu.Unlock()
	return awsCreds, nil
}

func (p *Provider) cachedCredentials(now time.Time) (aws.Credentials, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cachedCredentialsLocked(now)
}

func (p *Provider) cachedCredentialsLocked(now time.Time) (aws.Credentials, bool) {
	if !p.hasValidCachedCredentials(now) {
		return aws.Credentials{}, false
	}
	margin := p.refreshMargin
	if p.cachedLifetime > 0 && margin > p.cachedLifetime/2 {
		margin = p.cachedLifetime / 2
	}
	if now.Before(p.expiration.Add(-margin)) || now.Before(p.nextRefreshAttempt) {
		return p.cachedCreds, true
	}
	return aws.Credentials{}, false
}

func (p *Provider) validCachedCredentials(now time.Time) (aws.Credentials, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.hasValidCachedCredentials(now) {
		return aws.Credentials{}, false
	}
	return p.cachedCreds, true
}

func (p *Provider) useCachedCredentialsAfterFailure(now time.Time) (aws.Credentials, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.hasValidCachedCredentials(now) {
		return aws.Credentials{}, false
	}
	delay := p.refreshFailureDelay
	if remaining := p.expiration.Sub(now); delay > remaining/2 {
		delay = remaining / 2
	}
	p.nextRefreshAttempt = now.Add(delay)
	return p.cachedCreds, true
}

func (p *Provider) hasValidCachedCredentials(now time.Time) bool {
	return p.cachedCreds.CanExpire && p.cachedCreds.HasKeys() && now.Before(p.expiration)
}

// internal struct used for parsing JSON response
type createSessionResponse struct {
	CredentialSet []struct {
		Credentials struct {
			AccessKeyID     string `json:"accessKeyId"`
			SecretAccessKey string `json:"secretAccessKey"`
			SessionToken    string `json:"sessionToken"`
			Expiration      string `json:"expiration"`
		} `json:"credentials"`
	} `json:"credentialSet"`
}

type sessionCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
}

// helpers

func parsePrivateKey(pemBytes []byte) (crypto.PrivateKey, error) {
	var block *pem.Block
	block, _ = pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	// Support PKCS#1 RSA, SEC1 EC, and PKCS#8 RSA or EC keys.
	if block.Type == "RSA PRIVATE KEY" {
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}
	if block.Type == "EC PRIVATE KEY" {
		return x509.ParseECPrivateKey(block.Bytes)
	}
	// Preserve the existing PKCS#8 fallback for all other PEM block types.
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return k, nil
}

func signingAlgorithmForPrivateKey(privateKey crypto.PrivateKey) (string, error) {
	switch privateKey.(type) {
	case *rsa.PrivateKey:
		return "AWS4-X509-RSA-SHA256", nil
	case *ecdsa.PrivateKey:
		return "AWS4-X509-ECDSA-SHA256", nil
	default:
		return "", fmt.Errorf("unsupported private key type %T; expected RSA or ECDSA", privateKey)
	}
}

func validatePrivateKeyMatchesCertificate(privateKey crypto.PrivateKey, cert *x509.Certificate) error {
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		certKey, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("RSA private key requires a certificate with an RSA public key")
		}
		if !key.PublicKey.Equal(certKey) {
			return fmt.Errorf("RSA private key does not match certificate public key")
		}
	case *ecdsa.PrivateKey:
		certKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("EC private key requires a certificate with an EC public key")
		}
		if !key.PublicKey.Equal(certKey) {
			return fmt.Errorf("EC private key does not match certificate public key")
		}
	default:
		return fmt.Errorf("unsupported private key type %T; expected RSA or ECDSA", privateKey)
	}
	return nil
}

func signString(privateKey crypto.PrivateKey, stringToSign string) ([]byte, error) {
	digest := sha256Bytes([]byte(stringToSign))
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
	case *ecdsa.PrivateKey:
		return ecdsa.SignASN1(rand.Reader, key, digest)
	default:
		return nil, fmt.Errorf("unsupported private key type %T; expected RSA or ECDSA", privateKey)
	}
}

func parseCertificate(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func sha256Bytes(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}
