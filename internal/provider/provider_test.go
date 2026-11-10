// Copyright (c) Encryption Consulting LLC
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

var testProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"certsecure": providerserver.NewProtocol6WithError(New("test")()),
}

func TestMain(m *testing.M) {
	pollInitialInterval = 10 * time.Millisecond
	pollMaxInterval = 50 * time.Millisecond
	os.Exit(m.Run())
}

// testCSR returns a PEM CSR for cn with the given DNS SANs.
func testCSR(t *testing.T, cn string, dns ...string) string {
	t.Helper()
	return testCSRForKey(t, testKey(t), cn, dns...)
}

// testKey returns a new P-256 private key.
func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// testCSRForKey returns a PEM CSR signed by key, for cn with the given DNS SANs.
func testCSRForKey(t *testing.T, key *ecdsa.PrivateKey, cn string, dns ...string) string {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}, DNSNames: dns}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// providerBlock configures the provider against a fake CertSecure server.
func providerBlock(url string) string {
	return fmt.Sprintf(`
provider "certsecure" {
  url   = %q
  token = %q
}
`, url, fakeToken)
}
