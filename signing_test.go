package rolesanywhere

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"
)

type signingRoundTripper func(*http.Request) (*http.Response, error)

func (f signingRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func mustSigningKey(t *testing.T, curve elliptic.Curve) crypto.Signer {
	t.Helper()
	if curve != nil {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatalf("generate EC key: %v", err)
		}
		return key
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return key
}

func mustSigningKeyPEM(t *testing.T, key crypto.Signer, format string) []byte {
	t.Helper()
	var der []byte
	var err error
	var blockType string
	switch format {
	case "PKCS1":
		blockType = "RSA PRIVATE KEY"
		der = x509.MarshalPKCS1PrivateKey(key.(*rsa.PrivateKey))
	case "SEC1":
		blockType = "EC PRIVATE KEY"
		der, err = x509.MarshalECPrivateKey(key.(*ecdsa.PrivateKey))
	case "PKCS8":
		blockType = "PRIVATE KEY"
		der, err = x509.MarshalPKCS8PrivateKey(key)
	default:
		t.Fatalf("unknown test key format %q", format)
	}
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}

func mustSigningCertificate(t *testing.T, key, issuer crypto.Signer, now time.Time) ([]byte, *x509.Certificate) {
	t.Helper()
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test workload"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	ca := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "test CA"},
		PublicKey:             issuer.Public(),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, key.Public(), issuer)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse test certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), cert
}

// Reconstruct the signed request independently, then verify with the public key
// from the certificate actually sent. In particular, this detects the wrong
// algorithm in stringToSign and raw (rather than ASN.1) ECDSA signatures.
func verifySignedRequest(t *testing.T, r *http.Request, cert *x509.Certificate, algorithm string, now time.Time) {
	t.Helper()
	if r.Method != http.MethodPost || r.URL.Path != "/sessions" || r.URL.RawQuery != "" {
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL)
	}
	if got := r.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("unexpected content type: %q", got)
	}
	amzDate := now.UTC().Format("20060102T150405Z")
	if got := r.Header.Get("X-Amz-Date"); got != amzDate {
		t.Fatalf("unexpected signing date: %q", got)
	}
	encodedCert := base64.StdEncoding.EncodeToString(cert.Raw)
	if got := r.Header.Get("X-Amz-X509"); got != encodedCert {
		t.Fatal("request does not contain the expected certificate")
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read request body: %v", err)
	}
	payloadHash := sha256.Sum256(body)
	signedHeaders := "content-type;host;x-amz-date;x-amz-x509"
	canonicalHeaders := "content-type:application/json\nhost:" + r.Host +
		"\nx-amz-date:" + amzDate + "\nx-amz-x509:" + encodedCert + "\n"
	canonicalRequest := strings.Join([]string{
		"POST", "/sessions", "", canonicalHeaders, signedHeaders,
		fmt.Sprintf("%x", payloadHash),
	}, "\n")
	canonicalHash := sha256.Sum256([]byte(canonicalRequest))
	scope := now.UTC().Format("20060102") + "/us-east-1/rolesanywhere/aws4_request"
	stringToSign := strings.Join([]string{
		algorithm, amzDate, scope, fmt.Sprintf("%x", canonicalHash),
	}, "\n")
	digest := sha256.Sum256([]byte(stringToSign))

	prefix := algorithm + " Credential=" + cert.SerialNumber.String() + "/" + scope +
		", SignedHeaders=" + signedHeaders + ", Signature="
	authorization := r.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, prefix) {
		t.Fatalf("unexpected Authorization header: %q", authorization)
	}
	signature, err := hex.DecodeString(strings.TrimPrefix(authorization, prefix))
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
			t.Fatalf("RSA PKCS#1 v1.5 signature verification failed: %v", err)
		}
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(key, digest[:], signature) {
			t.Fatal("ECDSA ASN.1 signature verification failed")
		}
	default:
		t.Fatalf("unexpected test public key type %T", key)
	}
}

func TestProvider_Retrieve_SigningFormats(t *testing.T) {
	rsaKey := mustSigningKey(t, nil)
	ec256 := mustSigningKey(t, elliptic.P256())
	ec384 := mustSigningKey(t, elliptic.P384())
	ec521 := mustSigningKey(t, elliptic.P521())
	const rsaAlgorithm = "AWS4-X509-RSA-SHA256"
	const ecAlgorithm = "AWS4-X509-ECDSA-SHA256"
	tests := []struct {
		name      string
		key       crypto.Signer
		issuer    crypto.Signer
		format    string
		algorithm string
	}{
		{"RSA_PKCS1", rsaKey, rsaKey, "PKCS1", rsaAlgorithm},
		{"RSA_PKCS8", rsaKey, rsaKey, "PKCS8", rsaAlgorithm},
		{"EC_P256_SEC1", ec256, ec256, "SEC1", ecAlgorithm},
		{"EC_P256_PKCS8", ec256, ec256, "PKCS8", ecAlgorithm},
		{"EC_P384_SEC1", ec384, ec384, "SEC1", ecAlgorithm},
		{"EC_P384_PKCS8", ec384, ec384, "PKCS8", ecAlgorithm},
		{"EC_P521_SEC1", ec521, ec521, "SEC1", ecAlgorithm},
		{"EC_P521_PKCS8", ec521, ec521, "PKCS8", ecAlgorithm},
		{"RSA_leaf_EC_issuer", rsaKey, ec256, "PKCS1", rsaAlgorithm},
		{"EC_leaf_RSA_issuer", ec256, rsaKey, "SEC1", ecAlgorithm},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
			keyPEM := mustSigningKeyPEM(t, tt.key, tt.format)
			certPEM, cert := mustSigningCertificate(t, tt.key, tt.issuer, now)

			parsed, err := parsePrivateKey(keyPEM)
			if err != nil {
				t.Fatalf("parse private key: %v", err)
			}
			switch key := parsed.(type) {
			case *rsa.PrivateKey:
				if !key.PublicKey.Equal(tt.key.Public()) {
					t.Fatal("parsed RSA key differs from original")
				}
			case *ecdsa.PrivateKey:
				if !key.PublicKey.Equal(tt.key.Public()) {
					t.Fatal("parsed EC key differs from original")
				}
			default:
				t.Fatalf("unexpected parsed key type %T", parsed)
			}

			calls := 0
			p := NewProvider(WithPrivateKeyPath("key.pem"), WithCertificatePath("cert.pem"))
			p.now = func() time.Time { return now }
			p.readFile = func(path string) ([]byte, error) {
				if path == "key.pem" {
					return keyPEM, nil
				}
				return certPEM, nil
			}
			p.HTTPClient = &http.Client{Transport: signingRoundTripper(func(r *http.Request) (*http.Response, error) {
				calls++
				verifySignedRequest(t, r, cert, tt.algorithm, now)
				body := fmt.Sprintf(
					"{\"credentialSet\":[{\"credentials\":{\"accessKeyId\":\"AKIA_SIGNED\",\"secretAccessKey\":\"SECRET\",\"sessionToken\":\"TOKEN\",\"expiration\":%q}}]}",
					now.Add(time.Hour).Format(time.RFC3339),
				)
				return &http.Response{StatusCode: http.StatusCreated, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}
			for i := 0; i < 2; i++ {
				creds, err := p.Retrieve(context.Background())
				if err != nil {
					t.Fatalf("Retrieve: %v", err)
				}
				if creds.AccessKeyID != "AKIA_SIGNED" || creds.SecretAccessKey != "SECRET" || creds.SessionToken != "TOKEN" {
					t.Fatalf("unexpected credentials: %+v", creds)
				}
			}
			if calls != 1 {
				t.Fatalf("expected cached second retrieval, got %d requests", calls)
			}
		})
	}
}

func TestParsePrivateKey_InvalidPEM(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"not_PEM", []byte("not a private key")},
		{"malformed_PKCS1", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("bad")})},
		{"malformed_SEC1", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("bad")})},
		{"malformed_PKCS8", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("bad")})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parsePrivateKey(tt.data); err == nil {
				t.Fatal("expected private key parsing error")
			}
		})
	}
}

func TestProvider_Retrieve_KeyCertificateMismatch(t *testing.T) {
	rsaKey := mustSigningKey(t, nil)
	otherRSA := mustSigningKey(t, nil)
	ecKey := mustSigningKey(t, elliptic.P256())
	otherEC := mustSigningKey(t, elliptic.P256())
	tests := []struct {
		name    string
		key     crypto.Signer
		certKey crypto.Signer
		wantErr string
	}{
		{"RSA_different_key", rsaKey, otherRSA, "does not match"},
		{"EC_different_key", ecKey, otherEC, "does not match"},
		{"RSA_key_EC_certificate", rsaKey, ecKey, "requires a certificate with an RSA public key"},
		{"EC_key_RSA_certificate", ecKey, rsaKey, "requires a certificate with an EC public key"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPEM := mustSigningKeyPEM(t, tt.key, "PKCS8")
			certPEM, _ := mustSigningCertificate(t, tt.certKey, tt.certKey, time.Now())
			p := NewProvider(WithPrivateKeyPath("key.pem"), WithCertificatePath("cert.pem"))
			p.readFile = func(path string) ([]byte, error) {
				if path == "key.pem" {
					return keyPEM, nil
				}
				return certPEM, nil
			}
			p.HTTPClient = &http.Client{Transport: signingRoundTripper(func(*http.Request) (*http.Response, error) {
				t.Error("mismatched key must be rejected before sending a request")
				return nil, fmt.Errorf("unexpected request")
			})}
			_, err := p.Retrieve(context.Background())
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestProvider_Retrieve_UnsupportedPrivateKey(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate unsupported key: %v", err)
	}
	keyPEM := mustSigningKeyPEM(t, key, "PKCS8")
	p := NewProvider(WithPrivateKeyPath("key.pem"))
	p.readFile = func(path string) ([]byte, error) {
		if path != "key.pem" {
			t.Fatalf("unsupported key must be rejected before reading certificate")
		}
		return keyPEM, nil
	}
	_, err = p.Retrieve(context.Background())
	if err == nil || !strings.Contains(err.Error(), "unsupported private key type") {
		t.Fatalf("expected unsupported private key error, got %v", err)
	}
}
