// Copyright (c) Encryption Consulting LLC
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/smallstep/pkcs7"
)

const testToken = "test-token-value"

type testChain struct {
	Root, Intermediate, Leaf *x509.Certificate
}

var (
	chainOnce sync.Once
	chainVal  testChain
)

// synthChain builds a root -> intermediate -> leaf chain. Real certificates
// from CertSecure are never stored in the repository.
func synthChain(t *testing.T) testChain {
	t.Helper()
	chainOnce.Do(func() {
		mk := func(cn string, serial int64, isCA bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			tmpl := &x509.Certificate{
				SerialNumber:          big.NewInt(serial),
				Subject:               pkix.Name{CommonName: cn},
				NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
				NotAfter:              time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC),
				IsCA:                  isCA,
				BasicConstraintsValid: true,
				KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
				DNSNames:              []string{},
			}
			if !isCA {
				tmpl.KeyUsage = x509.KeyUsageDigitalSignature
				tmpl.DNSNames = []string{cn}
			}
			signer, signerKey := parent, parentKey
			if signer == nil {
				signer, signerKey = tmpl, key
			}
			der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
			if err != nil {
				t.Fatal(err)
			}
			c, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			return c, key
		}
		root, rootKey := mk("Test Root CA", 1, true, nil, nil)
		inter, interKey := mk("Test Issuing CA", 2, true, root, rootKey)
		leaf, _ := mk("tf-provider-test.example.com", 0x3400033ba9, false, inter, interKey)
		chainVal = testChain{Root: root, Intermediate: inter, Leaf: leaf}
	})
	return chainVal
}

// p7bPEM encodes certs as a PEM PKCS7 bundle, like /enrollment/download?type=p7b.
func p7bPEM(t *testing.T, certs ...*x509.Certificate) []byte {
	t.Helper()
	var der []byte
	for _, c := range certs {
		der = append(der, c.Raw...)
	}
	p7, err := pkcs7.DegenerateCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: p7})
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// newTestClient starts an httptest server and returns a client for it.
func newTestClient(t *testing.T, h http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := New(Config{
		URL:       srv.URL,
		Token:     testToken,
		UserAgent: "terraform-provider-certsecure/test",
		RetryWait: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c, srv
}

func writeJSON(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func ctx() context.Context { return context.Background() }
