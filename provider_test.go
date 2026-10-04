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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ---------- helpers ----------

func mustKeyAndCert(t *testing.T) (keyPEM, certPEM []byte) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		&key.PublicKey,
		key,
	)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return
}

// ---------- tests ----------

func TestProvider_Retrieve_Success(t *testing.T) {
	keyPEM, certPEM := mustKeyAndCert(t)

	fixedTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	expiry := fixedTime.Add(30 * time.Minute)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"credentialSet": []any{
				map[string]any{
					"credentials": map[string]any{
						"accessKeyId":     "AKIA_TEST",
						"secretAccessKey": "SECRET",
						"sessionToken":    "TOKEN",
						"expiration":      expiry.Format(time.RFC3339),
					},
				},
			},
		})
	}))
	defer srv.Close()

	p := NewProvider(
		WithPrivateKeyPath("key.pem"),
		WithCertificatePath("cert.pem"),
	)
	p.host = "rolesanywhere.test"
	p.endpoint = srv.URL
	p.HTTPClient = srv.Client()
	p.now = func() time.Time { return fixedTime }
	p.readFile = func(path string) ([]byte, error) {
		if path == "key.pem" {
			return keyPEM, nil
		}
		return certPEM, nil
	}

	creds, err := p.Retrieve(t.Context())
	if err != nil {
		t.Fatalf("Retrieve failed: %v", err)
	}

	if creds.AccessKeyID != "AKIA_TEST" {
		t.Fatalf("unexpected access key: %s", creds.AccessKeyID)
	}
}

func TestProvider_Retrieve_UsesCache(t *testing.T) {
	keyPEM, certPEM := mustKeyAndCert(t)

	var calls int32

	fixedTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	expiry := fixedTime.Add(time.Hour)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"credentialSet": []any{
				map[string]any{
					"credentials": map[string]any{
						"accessKeyId":     "AKIA_CACHE",
						"secretAccessKey": "SECRET",
						"sessionToken":    "TOKEN",
						"expiration":      expiry.Format(time.RFC3339),
					},
				},
			},
		})
	}))
	defer srv.Close()

	p := NewProvider(
		WithPrivateKeyPath("key.pem"),
		WithCertificatePath("cert.pem"),
	)
	p.host = "rolesanywhere.test"
	p.endpoint = srv.URL
	p.HTTPClient = srv.Client()
	p.now = func() time.Time { return fixedTime }
	p.readFile = func(path string) ([]byte, error) {
		if path == "key.pem" {
			return keyPEM, nil
		}
		return certPEM, nil
	}

	_, err := p.Retrieve(t.Context())
	if err != nil {
		t.Fatalf("first Retrieve failed: %v", err)
	}

	_, err = p.Retrieve(t.Context())
	if err != nil {
		t.Fatalf("second Retrieve failed: %v", err)
	}

	if calls != 1 {
		t.Fatalf("expected 1 CreateSession call, got %d", calls)
	}
}

func TestProvider_Retrieve_HTTPError(t *testing.T) {
	keyPEM, certPEM := mustKeyAndCert(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		if _, err := w.Write([]byte("boom")); err != nil {
			t.Errorf("write error response: %v", err)
		}
	}))
	defer srv.Close()

	p := NewProvider(
		WithPrivateKeyPath("key.pem"),
		WithCertificatePath("cert.pem"),
	)
	p.host = "rolesanywhere.test"
	p.endpoint = srv.URL
	p.HTTPClient = srv.Client()
	p.readFile = func(path string) ([]byte, error) {
		if path == "key.pem" {
			return keyPEM, nil
		}
		return certPEM, nil
	}

	_, err := p.Retrieve(t.Context())
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "CreateSession failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}
