// Copyright (c) Encryption Consulting LLC
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"testing"
)

func TestParseCSR(t *testing.T) {
	good := testCSR(t, "a.example.com")
	if _, err := parseCSR(good); err != nil {
		t.Fatalf("valid CSR rejected: %v", err)
	}
	if _, err := parseCSR("\n  " + good + "\n"); err != nil {
		t.Fatalf("surrounding whitespace should be accepted: %v", err)
	}
	for name, in := range map[string]string{
		"empty":      "",
		"not pem":    "hello",
		"wrong type": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
		"bad der":    "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n",
		"two csrs":   good + good,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseCSR(in); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestSANValidator(t *testing.T) {
	cases := []struct {
		kind sanKind
		in   string
		ok   bool
	}{
		{sanDNS, "app.example.com", true},
		{sanDNS, "*.example.com", true},
		{sanDNS, "host_name.corp", true},
		{sanDNS, "-bad.example.com", false},
		{sanDNS, "a..b", false},
		{sanDNS, "a b.com", false},
		{sanDNS, "a.com&dns=evil.com", false},
		{sanDNS, "a.com,b.com", false},
		{sanDNS, `a.com" & calc`, false},
		{sanIP, "192.0.2.1", true},
		{sanIP, "2001:db8::1", true},
		{sanIP, "192.0.2", false},
		{sanEmail, "ops@example.com", true},
		{sanEmail, "Ops <ops@example.com>", false},
		{sanURI, "https://app.example.com/x", true},
		{sanURI, "spiffe://example.com/ns/app", true},
		{sanURI, "urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a66", true},
		{sanURI, "/relative/path", false},
		{sanURI, "app.example.com", false},
		{sanDNS, "", false},
	}
	for _, tc := range cases {
		err := sanValidator{kind: tc.kind}.check(tc.in)
		if (err == nil) != tc.ok {
			t.Errorf("kind %d %q: err=%v, want ok=%v", tc.kind, tc.in, err, tc.ok)
		}
	}
}
