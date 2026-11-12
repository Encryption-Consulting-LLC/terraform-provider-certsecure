// Copyright (c) Encryption Consulting LLC
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestEnrollCSR_RequestBody(t *testing.T) {
	var got map[string]any
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/enrollment/enroll_csr" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q", ct)
		}
		b, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatal(err)
		}
		writeJSON(w, 200, fixture(t, "enroll_csr_200.json"))
	})

	resp, err := c.EnrollCSR(ctx(), EnrollCSRRequest{
		CSR: "PEM", CA: "Issuing CA", Template: "WebServer",
		Email:           []string{"user@example.com"},
		OverrideCSRSANs: true,
		SANAttributes: SANs{
			DNS: []string{"a.example.com"}, IP: []string{"192.0.2.1"},
			Email: []string{"ops@example.com"}, URI: []string{"spiffe://example/app"},
		}.Entries(),
		Tags:            []string{"terraform"},
		AdditionalNotes: "n",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.TaskID != "20795" || resp.EnrollmentID != 0 {
		t.Errorf("response = %+v", resp)
	}
	for k, want := range map[string]any{"csr": "PEM", "ca": "Issuing CA", "template": "WebServer", "override_csr_sans": true, "additional_notes": "n"} {
		if got[k] != want {
			t.Errorf("%s = %v, want %v", k, got[k], want)
		}
	}
	if emails, ok := got["email"].([]any); !ok || len(emails) != 1 || emails[0] != "user@example.com" {
		t.Errorf("email must be a JSON list, got %#v", got["email"])
	}
	san, ok := got["san_attributes"].([]any)
	if !ok {
		t.Fatalf("san_attributes must be a JSON list, got %#v", got["san_attributes"])
	}
	want := []string{"dns=a.example.com", "ipaddress=192.0.2.1", "email=ops@example.com", "url=spiffe://example/app"}
	if len(san) != len(want) {
		t.Fatalf("san_attributes = %v", san)
	}
	for i := range want {
		if san[i] != want[i] {
			t.Errorf("san_attributes[%d] = %v, want %v", i, san[i], want[i])
		}
	}
}

func TestEnrollCSR_OmitsOptionalFields(t *testing.T) {
	var got map[string]any
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		writeJSON(w, 200, fixture(t, "enroll_csr_200.json"))
	})
	if _, err := c.EnrollCSR(ctx(), EnrollCSRRequest{CSR: "PEM", CA: "c", Template: "t", SANAttributes: SANs{}.Entries()}); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"email", "san_attributes", "tags", "additional_notes"} {
		if _, ok := got[k]; ok {
			t.Errorf("%s should be omitted when unset", k)
		}
	}
	if got["override_csr_sans"] != false {
		t.Errorf("override_csr_sans should be sent as false")
	}
}

func TestEnrollCSR_Errors(t *testing.T) {
	cases := map[string]struct {
		status  int
		fixture string
		check   func(error) bool
		msg     string
	}{
		"invalid csr": {400, "enroll_csr_400_invalid_csr.json", IsBadRequest, "Invalid CSR"},
		"generic":     {400, "enroll_csr_400_generic.json", IsBadRequest, "Could not enroll the CSR"},
		"forbidden":   {403, "enroll_csr_403.json", IsForbidden, "User unauthorized"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { writeJSON(w, tc.status, fixture(t, tc.fixture)) })
			_, err := c.EnrollCSR(ctx(), EnrollCSRRequest{CSR: "x", CA: "c", Template: "t"})
			if !tc.check(err) || !strings.Contains(err.Error(), tc.msg) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestParseEnrollResponse(t *testing.T) {
	cases := []struct {
		name string
		body string
		task string
		eid  int64
	}{
		{"live shape", `{"TaskID":"20795"}`, "20795", 0},
		{"numeric task", `{"taskID": 7}`, "7", 0},
		{"with eid", `{"TaskID":"1","EnrollmentID":1509}`, "1", 1509},
		{"non-json", `ok`, "", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := parseEnrollResponse(200, []byte(tc.body))
			if r.TaskID != tc.task || r.EnrollmentID != tc.eid {
				t.Errorf("got task=%q eid=%d", r.TaskID, r.EnrollmentID)
			}
		})
	}
}

func TestGetEnrollmentDetails_Fixture(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/enrollment/enrolled_csr_details" || r.URL.Query().Get("eid") != "1477" {
			t.Errorf("unexpected request %s", r.URL)
		}
		writeJSON(w, 200, fixture(t, "enrolled_csr_details.json"))
	})
	d, err := c.GetEnrollmentDetails(ctx(), 1477)
	if err != nil {
		t.Fatal(err)
	}
	if d.EnrollmentID != 1477 || d.CertificateAuthority != "Example Issuing CA" || d.Template != "WebServer" || d.Status != "active" || !d.CertAvailable {
		t.Errorf("unexpected details %+v", d)
	}
	if len(d.SANDNSNames) != 1 {
		t.Errorf("sanDNSNames = %v", d.SANDNSNames)
	}
}

func TestDownloadCert_Formats(t *testing.T) {
	ch := synthChain(t)
	pemBody := []byte(EncodePEM(ch.Leaf))
	formats := map[string][]byte{
		"pem":    pemBody,
		"der":    ch.Leaf.Raw,
		"base64": []byte(base64.StdEncoding.EncodeToString(ch.Leaf.Raw)),
	}
	for name, body := range formats {
		t.Run(name, func(t *testing.T) {
			c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/enrollment/download_cert" || r.URL.Query().Get("eid") != "7" {
					t.Errorf("unexpected request %s", r.URL)
				}
				// CertSecure serves the PEM as text/html.
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = w.Write(body)
			})
			cert, err := c.DownloadCert(ctx(), 7)
			if err != nil {
				t.Fatal(err)
			}
			if !cert.Equal(ch.Leaf) {
				t.Error("certificate mismatch")
			}
		})
	}
}

func TestDownloadCert_400(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 400, fixture(t, "download_cert_400.json")) })
	_, err := c.DownloadCert(ctx(), 7)
	if !IsBadRequest(err) {
		t.Fatalf("want 400, got %v", err)
	}
}

func TestDownloadChain_P7B(t *testing.T) {
	ch := synthChain(t)
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if r.URL.Path != "/enrollment/download" || q.Get("type") != "p7b" || q.Get("eid") != "7" {
			t.Errorf("unexpected request %s", r.URL)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// Same order as CertSecure: root, intermediate, leaf.
		_, _ = w.Write(p7bPEM(t, ch.Root, ch.Intermediate, ch.Leaf))
	})
	certs, err := c.DownloadChain(ctx(), 7)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 3 {
		t.Fatalf("got %d certs", len(certs))
	}
}

func TestGetTrustChain_Fixture(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, fixture(t, "view_trust_chain.json")) })
	entries, err := c.GetTrustChain(ctx(), 1477)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 || entries[0].Level != "root" || entries[2].Level != "leaf" {
		t.Errorf("unexpected entries %+v", entries)
	}
	if entries[0].Fingerprints.SHA256 == "" {
		t.Error("fingerprint not decoded")
	}
}

func TestGetTrustChain_UnknownIsEmpty(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, []byte("[]")) })
	entries, err := c.GetTrustChain(ctx(), 99999999)
	if err != nil || len(entries) != 0 {
		t.Fatalf("got %v, %v", entries, err)
	}
}

func TestGetEnrollmentDetailsByTaskID(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("taskID") != "20798" || r.URL.Query().Get("eid") != "" {
			t.Errorf("unexpected query %s", r.URL.RawQuery)
		}
		writeJSON(w, 200, fixture(t, "enrolled_csr_details_san.json"))
	})
	d, err := c.GetEnrollmentDetailsByTaskID(ctx(), "20798")
	if err != nil {
		t.Fatal(err)
	}
	if d.EnrollmentID != 1512 || len(d.SANDNSNames) != 2 || len(d.SANIPAddresses) != 1 {
		t.Errorf("unexpected details %+v", d)
	}
}

func TestGetEnrollmentDetailsBySerial(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("serialNum") != "3400033ba9" || q.Get("ca") != "Example Issuing CA" || q.Get("eid") != "" {
			t.Errorf("unexpected query %s", r.URL.RawQuery)
		}
		writeJSON(w, 200, fixture(t, "enrolled_csr_details.json"))
	})
	d, err := c.GetEnrollmentDetailsBySerial(ctx(), "3400033ba9", "Example Issuing CA")
	if err != nil {
		t.Fatal(err)
	}
	if d.EnrollmentID != 1477 || d.CertificateAuthority != "Example Issuing CA" || !d.CertAvailable {
		t.Errorf("unexpected details %+v", d)
	}
}

func TestGetEnrollmentDetailsBySerial_InventoryOnly(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, fixture(t, "enrolled_csr_details_inventory.json"))
	})
	d, err := c.GetEnrollmentDetailsBySerial(ctx(), "3400033ba9", "Example Issuing CA")
	if err != nil {
		t.Fatal(err)
	}
	if d.EnrollmentID != 0 || d.CertificateAuthority != "Example Issuing CA" {
		t.Errorf("unexpected details %+v", d)
	}
}

func TestGetEnrollmentDetailsBySerial_NotFound(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 404, []byte(`{"Error": "Not Found"}`))
	})
	_, err := c.GetEnrollmentDetailsBySerial(ctx(), "0badc0de", "Example Issuing CA")
	if !IsNotFound(err) {
		t.Errorf("err = %v, want 404", err)
	}
}

func TestEnrollmentDetails_Pending(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, fixture(t, "enrolled_csr_details_pending.json"))
	})
	d, err := c.GetEnrollmentDetails(ctx(), 1510)
	if err != nil {
		t.Fatal(err)
	}
	if d.Status != "pending" || d.CertAvailable || d.ExpiresOn != "" {
		t.Errorf("unexpected details %+v", d)
	}
}

func TestDownloadChain_MislabeledP7B(t *testing.T) {
	ch := synthChain(t)
	// Some deployments label the PKCS#7 bundle "CERTIFICATE".
	body := strings.Replace(string(p7bPEM(t, ch.Root, ch.Intermediate, ch.Leaf)), "PKCS7", "CERTIFICATE", 2)
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) })
	certs, err := c.DownloadChain(ctx(), 7)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 3 {
		t.Fatalf("got %d certs", len(certs))
	}
}

func TestRenewCSR_RequestBody(t *testing.T) {
	var got map[string]any
	calls := 0
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost || r.URL.Path != "/enrollment/renew_csr" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		b, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatal(err)
		}
		writeJSON(w, 200, []byte(`{"TaskID": "30001"}`))
	})

	resp, err := c.RenewCSR(ctx(), RenewCSRRequest{
		EID: 1501,
		EnrollCSRRequest: EnrollCSRRequest{
			CSR: "PEM", CA: "Issuing CA", Template: "WebServer",
			Email:         []string{"user@example.com"},
			SANAttributes: SANs{DNS: []string{"a.example.com"}}.Entries(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || resp.TaskID != "30001" {
		t.Errorf("calls = %d, response = %+v", calls, resp)
	}
	for k, want := range map[string]any{"eid": float64(1501), "csr": "PEM", "ca": "Issuing CA", "template": "WebServer", "override_csr_sans": false} {
		if got[k] != want {
			t.Errorf("%s = %v, want %v", k, got[k], want)
		}
	}
	if san, ok := got["san_attributes"].([]any); !ok || len(san) != 1 || san[0] != "dns=a.example.com" {
		t.Errorf("san_attributes = %#v", got["san_attributes"])
	}
	if _, ok := got["owner"]; ok {
		t.Error("owner must not be sent: it is inherited")
	}
}

func TestRenewCSR_Errors(t *testing.T) {
	cases := map[string]struct {
		status int
		body   string
		check  func(error) bool
		msg    string
	}{
		"bad request": {400, `{"Error": "Invalid CSR"}`, IsBadRequest, "Invalid CSR"},
		"forbidden":   {403, `{"Error": "User is not authorized to renew this certificate"}`, IsForbidden, "not authorized to renew"},
		"not found":   {404, `{"Error": "No enrollment record with eid 9"}`, IsNotFound, "No enrollment record"},
		"conflict":    {409, `{"Error": "certificate is not renewable (status: revoked)"}`, IsConflict, "status: revoked"},
		"server":      {500, `{"Error": "Could not validate CSR against CA policy. Error: x"}`, IsServerError, "CA policy"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			calls := 0
			c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				writeJSON(w, tc.status, []byte(tc.body))
			})
			_, err := c.RenewCSR(ctx(), RenewCSRRequest{EID: 9, EnrollCSRRequest: EnrollCSRRequest{CSR: "x"}})
			if !tc.check(err) || !strings.Contains(err.Error(), tc.msg) {
				t.Fatalf("got %v", err)
			}
			if calls != 1 {
				t.Errorf("renew_csr must never be retried, got %d calls", calls)
			}
		})
	}
}

func TestRevokeCert_Request(t *testing.T) {
	calls := 0
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost || r.URL.Path != "/enrollment/revoke_cert" || r.URL.Query().Get("eid") != "1501" {
			t.Errorf("unexpected %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
		}
		if b, _ := io.ReadAll(r.Body); len(b) != 0 {
			t.Errorf("unexpected body %q", b)
		}
		// Like the real API: the task ID as plain text, served as text/html.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("22041"))
	})
	taskID, err := c.RevokeCert(ctx(), 1501)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || taskID != "22041" {
		t.Errorf("calls = %d, taskID = %q", calls, taskID)
	}
}

func TestParseTaskID(t *testing.T) {
	for body, want := range map[string]string{
		"22041":                 "22041",
		" 22041\n":              "22041",
		`"22041"`:               "22041",
		`{"TaskID": "22041"}`:   "22041",
		`{"taskID": 22041}`:     "22041",
		`{"message": "queued"}`: "",
		"<html>error</html>":    "",
		"":                      "",
	} {
		if got := parseTaskID([]byte(body)); got != want {
			t.Errorf("parseTaskID(%q) = %q, want %q", body, got, want)
		}
	}
}

func TestRevokeCert_Errors(t *testing.T) {
	cases := map[string]struct {
		status int
		body   string
		check  func(error) bool
		msg    string
	}{
		"forbidden": {403, `{"Error": "User not authorized"}`, IsForbidden, "not authorized"},
		"not found": {404, `{"Error": "Could not find active certificate with eid 9"}`, IsNotFound, "active certificate"},
		"server":    {500, `{"Error": "Could not revoke certificate, Please check logs for more details."}`, IsServerError, "Could not revoke"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			calls := 0
			c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				writeJSON(w, tc.status, []byte(tc.body))
			})
			_, err := c.RevokeCert(ctx(), 9)
			if !tc.check(err) || !strings.Contains(err.Error(), tc.msg) {
				t.Fatalf("got %v", err)
			}
			if calls != 1 {
				t.Errorf("revoke_cert must never be retried, got %d calls", calls)
			}
		})
	}
}
