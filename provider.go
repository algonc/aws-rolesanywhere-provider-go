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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// Provider implements aws.CredentialsProvider and obtains temporary credentials
// from AWS RolesAnywhere by performing the SigV4-X509 RSA signing flow and calling CreateSession.
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
	mu            sync.Mutex
	cachedCreds   aws.Credentials
	expiration    time.Time
	refreshMargin time.Duration // how long before expiry we proactively refresh

	// test hooks
	host     string
	endpoint string
	now      func() time.Time
	readFile func(string) ([]byte, error)
}

// NewProvider constructs a new Provider with sensible defaults.
func NewProvider(opts ...Option) *Provider {
	p := &Provider{
		Region:          "us-east-1",
		DurationSeconds: 3600,
		refreshMargin:   5 * time.Minute,
		HTTPClient:      http.DefaultClient,
		now:             time.Now,
		readFile:        os.ReadFile,
	}
	for _, o := range opts {
		o(p)
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

// Retrieve implements aws.CredentialsProvider
func (p *Provider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	// quick path: return cached creds if still valid
	p.mu.Lock()
	now := p.now().UTC()
	if p.cachedCreds.CanExpire && now.Add(p.refreshMargin).Before(p.expiration) && p.cachedCreds.AccessKeyID != "" {
		creds := p.cachedCreds
		p.mu.Unlock()
		return creds, nil
	}
	p.mu.Unlock()

	// Acquire new credentials
	creds, err := p.createSessionAndGetCredentials(ctx)
	if err != nil {
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

	// cache
	p.mu.Lock()
	p.cachedCreds = awsCreds
	p.expiration = creds.Expiration
	p.mu.Unlock()

	return awsCreds, nil
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

// createSessionAndGetCredentials performs the signing and CreateSession call.
func (p *Provider) createSessionAndGetCredentials(ctx context.Context) (sessionCredentials, error) {
	// 1) read private key
	keyPEM, err := p.readFile(p.PrivateKeyPath)
	if err != nil {
		return sessionCredentials{}, fmt.Errorf("reading private key: %w", err)
	}
	privKey, err := parsePrivateKey(keyPEM)
	if err != nil {
		return sessionCredentials{}, fmt.Errorf("parsing private key: %w", err)
	}
	rsaKey, ok := privKey.(*rsa.PrivateKey)
	if !ok {
		return sessionCredentials{}, fmt.Errorf("private key is not RSA")
	}

	// 2) read certificate
	certPEM, err := p.readFile(p.CertificatePath)
	if err != nil {
		return sessionCredentials{}, fmt.Errorf("reading certificate: %w", err)
	}
	cert, err := parseCertificate(certPEM)
	if err != nil {
		return sessionCredentials{}, fmt.Errorf("parsing certificate: %w", err)
	}

	certDerBase64 := base64.StdEncoding.EncodeToString(cert.Raw)
	serialDec := cert.SerialNumber.String()

	// 3) build request payload
	payload := map[string]interface{}{
		"durationSeconds": p.DurationSeconds,
		"profileArn":      p.ProfileArn,
		"roleArn":         p.RoleArn,
		"sessionName":     p.SessionName,
		"trustAnchorArn":  p.TrustAnchorArn,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return sessionCredentials{}, fmt.Errorf("marshal payload: %w", err)
	}

	// 4) prepare SigV4-X509 signing values
	service := "rolesanywhere"
	host := p.host
	endpoint := p.endpoint
	if host == "" {
		host = fmt.Sprintf("%s.%s.amazonaws.com", service, p.Region)
	}
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://%s/sessions", host)
	}
	now := p.now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	contentType := "application/json"
	canonicalURI := "/sessions"
	canonicalQuerystring := ""

	// canonical headers (lowercase, sorted)
	canonicalHeaders := strings.Join([]string{
		"content-type:" + contentType,
		"host:" + host,
		"x-amz-date:" + amzDate,
		"x-amz-x509:" + certDerBase64,
	}, "\n") + "\n"

	signedHeaders := "content-type;host;x-amz-date;x-amz-x509"

	payloadHash := sha256Hex(payloadBytes)

	canonicalRequest := strings.Join([]string{
		"POST",
		canonicalURI,
		canonicalQuerystring,
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	algorithm := "AWS4-X509-RSA-SHA256"
	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, p.Region, service)

	stringToSign := strings.Join([]string{
		algorithm,
		amzDate,
		credentialScope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	// sign stringToSign with RSA SHA256
	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, sha256Bytes([]byte(stringToSign)))
	if err != nil {
		return sessionCredentials{}, fmt.Errorf("signing string: %w", err)
	}

	signatureHex := hex.EncodeToString(signature)

	authorizationHeader := fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		algorithm, serialDec, credentialScope, signedHeaders, signatureHex)

	// 5) perform HTTP POST
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(payloadBytes))
	if err != nil {
		return sessionCredentials{}, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-X509", certDerBase64)
	req.Header.Set("Authorization", authorizationHeader)
	req.Header.Set("Accept", "application/json")

	client := p.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return sessionCredentials{}, fmt.Errorf("calling CreateSession: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 201 {
		return sessionCredentials{}, fmt.Errorf("CreateSession failed: status=%d body=%s", resp.StatusCode, string(bodyBytes))
	}

	var parsed createSessionResponse
	if err := json.Unmarshal(bodyBytes, &parsed); err != nil {
		return sessionCredentials{}, fmt.Errorf("parsing CreateSession response: %w (body=%s)", err, string(bodyBytes))
	}

	if len(parsed.CredentialSet) == 0 {
		return sessionCredentials{}, fmt.Errorf("no credentialSet in response")
	}

	c := parsed.CredentialSet[0].Credentials
	expiry, err := time.Parse(time.RFC3339, c.Expiration)
	if err != nil {
		// fallback: try without TZ (rare)
		expiry, err = time.Parse("2006-01-02T15:04:05", c.Expiration)
		if err != nil {
			return sessionCredentials{}, fmt.Errorf("parsing expiration: %w (val=%s)", err, c.Expiration)
		}
	}

	return sessionCredentials{
		AccessKeyID:     c.AccessKeyID,
		SecretAccessKey: c.SecretAccessKey,
		SessionToken:    c.SessionToken,
		Expiration:      expiry,
	}, nil
}

// helpers

func parsePrivateKey(pemBytes []byte) (interface{}, error) {
	var block *pem.Block
	block, _ = pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	// support PKCS1, PKCS8
	if block.Type == "RSA PRIVATE KEY" {
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}
	// assume PKCS8
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return k, nil
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
