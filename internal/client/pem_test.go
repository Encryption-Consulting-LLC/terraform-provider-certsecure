// Copyright (c) Encryption Consulting LLC
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestParseCertificates_Errors(t *testing.T) {
	for name, body := range map[string]string{
		"empty":   "",
		"garbage": "not a certificate",
		"csr pem": "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseCertificates([]byte(body)); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestParseCertificates_MixedPEM(t *testing.T) {
	ch := synthChain(t)
	body := EncodePEM(ch.Leaf) + string(p7bPEM(t, ch.Intermediate, ch.Root))
	certs, err := ParseCertificates([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 3 {
		t.Fatalf("got %d certs", len(certs))
	}
}

func TestParseCertificates_DERPKCS7(t *testing.T) {
	ch := synthChain(t)
	pemP7 := p7bPEM(t, ch.Root, ch.Leaf)
	certs, err := ParseCertificates(pemP7)
	if err != nil || len(certs) != 2 {
		t.Fatalf("got %d, %v", len(certs), err)
	}
}

func TestBuildChain_IssuerFirst(t *testing.T) {
	ch := synthChain(t)
	orders := map[string][]*x509.Certificate{
		"server order (root first)": {ch.Root, ch.Intermediate, ch.Leaf},
		"already issuer first":      {ch.Leaf, ch.Intermediate, ch.Root},
		"shuffled with dup":         {ch.Intermediate, ch.Leaf, ch.Root, ch.Intermediate},
	}
	for name, pool := range orders {
		t.Run(name, func(t *testing.T) {
			chain := BuildChain(ch.Leaf, pool)
			if len(chain) != 2 || !chain[0].Equal(ch.Intermediate) || !chain[1].Equal(ch.Root) {
				var names []string
				for _, c := range chain {
					names = append(names, c.Subject.CommonName)
				}
				t.Fatalf("got %v, want [intermediate root]", names)
			}
		})
	}
}

func TestBuildChain_KeepsUnrelated(t *testing.T) {
	ch := synthChain(t)
	chain := BuildChain(ch.Intermediate, []*x509.Certificate{ch.Leaf, ch.Root})
	if len(chain) != 2 || !chain[0].Equal(ch.Root) || !chain[1].Equal(ch.Leaf) {
		t.Fatalf("unexpected chain")
	}
}

func TestEncodePEMAndSerial(t *testing.T) {
	ch := synthChain(t)
	out := EncodePEM(ch.Intermediate, ch.Root)
	if strings.Count(out, "-----BEGIN CERTIFICATE-----") != 2 {
		t.Fatal(out)
	}
	if got := SerialHex(ch.Leaf); got != "3400033ba9" {
		t.Errorf("serial = %q", got)
	}
}

// A DER certificate can end in a byte that is also ASCII whitespace (the last
// signature byte is random). It must not be trimmed before parsing.
func TestParseCertificates_DERTrailingWhitespaceByte(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "der.example.com"},
		NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)}
	for i := 0; i < 5000; i++ {
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.ContainsRune(" \t\n\v\f\r", rune(der[len(der)-1])) {
			continue
		}
		certs, err := ParseCertificates(der)
		if err != nil {
			t.Fatalf("DER ending in %#x: %v", der[len(der)-1], err)
		}
		if len(certs) != 1 || !bytes.Equal(certs[0].Raw, der) {
			t.Fatal("certificate mismatch")
		}
		return
	}
	t.Fatal("no certificate ending in a whitespace byte generated")
}
