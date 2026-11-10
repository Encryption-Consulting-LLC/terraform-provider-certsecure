// Copyright (c) Encryption Consulting LLC
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

func TestNew_Validation(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want string
	}{
		{"missing url", Config{Token: "x"}, "URL is required"},
		{"missing token", Config{URL: "https://certsecure.example.com"}, "token is required"},
		{"bad scheme", Config{URL: "ftp://certsecure.example.com", Token: "x"}, "scheme must be"},
		{"no host", Config{URL: "https://", Token: "x"}, "missing host"},
		{"bad bundle", Config{URL: "https://certsecure.example.com", Token: "x", CABundlePEM: "not pem"}, "ca_bundle_pem"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want error containing %q", err, tc.want)
			}
		})
	}
}

func TestRequest_HeadersAndBasePath(t *testing.T) {
	var gotAuth, gotUA, gotPath string
	srv := func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotUA, gotPath = r.Header.Get("Authorization"), r.Header.Get("User-Agent"), r.URL.Path
		_, _ = w.Write([]byte("True"))
	}
	c, s := newTestClient(t, srv)

	// A base URL with a path prefix and trailing slash is joined cleanly.
	c2, err := New(Config{URL: s.URL + "/api/", Token: "Bearer " + testToken, UserAgent: "ua/1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := c2.CheckToken(ctx()); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/check_token" {
		t.Errorf("path = %q", gotPath)
	}
	if gotAuth != "Bearer "+testToken {
		t.Errorf("a token given with a Bearer prefix must not be double-prefixed, got %q", gotAuth)
	}

	if err := c.CheckToken(ctx()); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer "+testToken {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotUA != "terraform-provider-certsecure/test" {
		t.Errorf("User-Agent = %q", gotUA)
	}
}

func TestUnauthenticatedEndpoints_NoAuthHeader(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("%s sent an Authorization header", r.URL.Path)
		}
		switch r.URL.Path {
		case "/version":
			writeJSON(w, 200, fixture(t, "version.json"))
		case "/check":
			_, _ = w.Write([]byte("True"))
		}
	})
	if err := c.Check(ctx()); err != nil {
		t.Fatal(err)
	}
	v, err := c.Version(ctx())
	if err != nil {
		t.Fatal(err)
	}
	if v.Backend != "3.4" || v.Mode != "saas" {
		t.Errorf("version = %+v", v)
	}
}

func TestCheckToken_401(t *testing.T) {
	for _, f := range []string{"error_401_invalid.json", "error_401_missing.json"} {
		t.Run(f, func(t *testing.T) {
			body := fixture(t, f)
			c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 401, body) })
			err := c.CheckToken(ctx())
			if !IsUnauthorized(err) {
				t.Fatalf("want 401, got %v", err)
			}
			if !strings.Contains(err.Error(), "Token is") {
				t.Errorf("error should carry API message: %v", err)
			}
		})
	}
}

func TestGet_RetriesOn5xx(t *testing.T) {
	var calls int32
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) < 3 {
			writeJSON(w, 503, []byte(`{"Error":"busy"}`))
			return
		}
		_, _ = w.Write([]byte("True"))
	})
	if err := c.CheckToken(ctx()); err != nil {
		t.Fatalf("expected success on third attempt: %v", err)
	}
	if calls != 3 {
		t.Errorf("calls = %d, want 3", calls)
	}
}

func TestGet_GivesUpAfterThreeAttempts(t *testing.T) {
	var calls int32
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		writeJSON(w, 500, []byte(`{"Error":"boom"}`))
	})
	err := c.CheckToken(ctx())
	if !IsServerError(err) {
		t.Fatalf("want 5xx error, got %v", err)
	}
	if calls != 3 {
		t.Errorf("calls = %d, want 3", calls)
	}
}

func TestGet_NoRetryOn4xx(t *testing.T) {
	var calls int32
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		writeJSON(w, 404, fixture(t, "enrolled_csr_details_404.json"))
	})
	_, err := c.GetEnrollmentDetails(ctx(), 99999999)
	if !IsNotFound(err) {
		t.Fatalf("want 404, got %v", err)
	}
	if !strings.Contains(err.Error(), "Enrollment ID 99999999 not found") {
		t.Errorf("message not extracted: %v", err)
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1", calls)
	}
}

func TestEnrollCSR_NeverRetried(t *testing.T) {
	var calls int32
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		writeJSON(w, 502, []byte(`{"Error":"bad gateway"}`))
	})
	_, err := c.EnrollCSR(ctx(), EnrollCSRRequest{CSR: "x", CA: "ca", Template: "t"})
	if !IsServerError(err) {
		t.Fatalf("want 5xx, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("enroll_csr was attempted %d times; it must never be retried", calls)
	}
}

func TestLogging_NeverContainsToken(t *testing.T) {
	var logged []string
	c, s := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 401, []byte(`{"message":"Token is invalid!"}`))
	})
	c2, err := New(Config{URL: s.URL, Token: testToken, RetryWait: 1, Logger: func(_ context.Context, msg string, f map[string]any) {
		logged = append(logged, msg+fmt.Sprint(f))
	}})
	if err != nil {
		t.Fatal(err)
	}
	_ = c.CheckToken(ctx())
	_ = c2.CheckToken(ctx())
	_, _ = c2.EnrollCSR(ctx(), EnrollCSRRequest{CSR: "x", CA: "c", Template: "t"})
	if len(logged) == 0 {
		t.Fatal("expected log lines")
	}
	for _, l := range logged {
		if strings.Contains(l, testToken) || strings.Contains(l, "Bearer") {
			t.Fatalf("log line leaks credentials: %s", l)
		}
	}
}
