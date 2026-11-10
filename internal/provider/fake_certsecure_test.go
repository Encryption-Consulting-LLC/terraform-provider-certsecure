// Copyright (c) Encryption Consulting LLC
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/smallstep/pkcs7"
)

// issueMode controls how the fake CertSecure processes an enrollment.
type issueMode int

const (
	modeIssue    issueMode = iota // issued after a few polls
	modeApproval                  // waits for CA manager approval
	modeDenied                    // denied by policy
	modeStuck                     // never progresses
	modeWrongKey                  // issues a certificate for a different key
)

const fakeToken = "fake-token"

type fakeEnrollment struct {
	eid      int64
	taskID   string
	ca       string
	template string
	emails   []string
	csr      *x509.CertificateRequest
	cert     *x509.Certificate
	polls    int
	mode     issueMode
	status   string
	// renewedFrom is the eid this enrollment renewed (renew_csr), or 0.
	renewedFrom int64
}

// fakeRevocation is a revoke_cert task.
type fakeRevocation struct {
	taskID string
	eid    int64
	polls  int
	mode   issueMode
}

// fakeCertSecure is an in-memory CertSecure API that mimics the asynchronous
// behavior observed on real deployments: enroll_csr returns only a TaskID,
// the enrollment record appears after the task leaves INITIALIZED, and the
// certificate becomes available once the task is OK.
type fakeCertSecure struct {
	t   *testing.T
	srv *httptest.Server

	mu          sync.Mutex
	mode        issueMode
	nextEID     int64
	nextTask    int
	byEID       map[int64]*fakeEnrollment
	byTask      map[string]*fakeEnrollment
	enrollCalls int
	lastEnroll  map[string]any
	renewCalls  int
	lastRenew   map[string]any
	// renewError, when non-zero, is the HTTP status renew_csr answers with.
	renewError  int
	revokeCalls int
	// revokeError, when non-zero, is the HTTP status revoke_cert answers with.
	revokeError int
	// revokeMode controls how new revocation tasks proceed (modeIssue: complete).
	revokeMode  issueMode
	revocations map[string]*fakeRevocation

	// Issued certificates are valid from issueAt for validity.
	issueAt  time.Time
	validity time.Duration

	rootKey, interKey *ecdsa.PrivateKey
	root, inter       *x509.Certificate
}

func newFakeCertSecure(t *testing.T) *fakeCertSecure {
	t.Helper()
	issueAt := time.Date(2026, 10, 22, 1, 39, 3, 0, time.UTC)
	f := &fakeCertSecure{
		t: t, nextEID: 1500, nextTask: 20000, byEID: map[int64]*fakeEnrollment{}, byTask: map[string]*fakeEnrollment{},
		revocations: map[string]*fakeRevocation{},
		issueAt:     issueAt, validity: time.Date(2028, 10, 21, 1, 39, 3, 0, time.UTC).Sub(issueAt),
	}
	f.root, f.rootKey = makeCA(t, "Fake Root CA", nil, nil)
	f.inter, f.interKey = makeCA(t, "Fake Issuing CA", f.root, f.rootKey)
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func makeCA(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, key
}

func (f *fakeCertSecure) setMode(m issueMode) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mode = m
}

func (f *fakeCertSecure) deleteEnrollment(eid int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.byEID, eid)
}

func (f *fakeCertSecure) enrollCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.enrollCalls
}

func (f *fakeCertSecure) lastEnrollBody() map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastEnroll
}

func (f *fakeCertSecure) renewCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.renewCalls
}

func (f *fakeCertSecure) lastRenewBody() map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastRenew
}

func (f *fakeCertSecure) setRenewError(status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.renewError = status
}

func (f *fakeCertSecure) revokeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.revokeCalls
}

func (f *fakeCertSecure) setRevokeError(status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revokeError = status
}

func (f *fakeCertSecure) setRevokeMode(m issueMode) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revokeMode = m
}

// setStatus changes the status of eid, e.g. to revoke or expire it outside Terraform.
func (f *fakeCertSecure) setStatus(eid int64, status string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.byEID[eid].status = status
}

func (f *fakeCertSecure) setIssueAt(at time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issueAt = at
}

// setTaskMode changes how an already submitted request proceeds, e.g. to
// approve a request waiting for approval (modeIssue).
func (f *fakeCertSecure) setTaskMode(taskID string, m issueMode) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.byTask[taskID].mode = m
}

// enrollment returns a copy of the enrollment record for eid.
func (f *fakeCertSecure) enrollment(eid int64) fakeEnrollment {
	f.mu.Lock()
	defer f.mu.Unlock()
	return *f.byEID[eid]
}

func (f *fakeCertSecure) issue(e *fakeEnrollment) {
	pub := e.csr.PublicKey
	if e.mode == modeWrongKey {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pub = &k.PublicKey
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x3400000000 + e.eid), Subject: e.csr.Subject, DNSNames: e.csr.DNSNames,
		NotBefore: f.issueAt, NotAfter: f.issueAt.Add(f.validity),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, f.inter, pub, f.interKey)
	if err != nil {
		f.t.Errorf("issuing: %v", err)
		return
	}
	e.cert, _ = x509.ParseCertificate(der)
	e.status = "active"
}

// newEnrollment queues a request for body's CSR, or answers 400 and returns
// nil if the CSR is invalid.
func (f *fakeCertSecure) newEnrollment(w http.ResponseWriter, body map[string]any) *fakeEnrollment {
	block, _ := pem.Decode([]byte(fmt.Sprint(body["csr"])))
	if block == nil {
		writeJSONResp(w, 400, map[string]string{"Error": "Invalid CSR"})
		return nil
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		writeJSONResp(w, 400, map[string]string{"Error": "Invalid CSR"})
		return nil
	}
	f.nextTask++
	e := &fakeEnrollment{taskID: strconv.Itoa(f.nextTask), ca: fmt.Sprint(body["ca"]), template: fmt.Sprint(body["template"]), csr: csr, mode: f.mode, status: "pending"}
	if emails, ok := body["email"].([]any); ok {
		for _, em := range emails {
			e.emails = append(e.emails, fmt.Sprint(em))
		}
	}
	f.byTask[e.taskID] = e
	return e
}

func writeJSONResp(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeCertSecure) handle(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/check", "/version":
		writeJSONResp(w, 200, map[string]string{"Backend": "3.4", "Frontend": "3.4", "mode": "test"})
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+fakeToken {
		writeJSONResp(w, 401, map[string]string{"message": "Token is invalid!"})
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	q := r.URL.Query()

	switch r.URL.Path {
	case "/check_token":
		_, _ = w.Write([]byte("True"))

	case "/available_ca", "/template/ca", "/enrollment/templates":
		name := map[string]string{"/available_ca": "available_ca.json", "/template/ca": "template_ca.json", "/enrollment/templates": "enrollment_templates.json"}[r.URL.Path]
		if r.URL.Path == "/template/ca" && q.Get("ca") != "Example Issuing CA" {
			writeJSONResp(w, 200, map[string]any{})
			return
		}
		b, err := os.ReadFile(filepath.Join("..", "client", "testdata", name))
		if err != nil {
			f.t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)

	case "/enrollment/enroll_csr":
		f.enrollCalls++
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSONResp(w, 400, map[string]string{"Error": "Could not enroll the CSR. See the CertSecure log for the reason."})
			return
		}
		f.lastEnroll = body
		e := f.newEnrollment(w, body)
		if e == nil {
			return
		}
		writeJSONResp(w, 200, map[string]string{"TaskID": e.taskID})

	case "/enrollment/renew_csr":
		// Mirrors the backend's renew-with-CSR: the old certificate stays
		// active and the new enrollment records renewedFrom.
		f.renewCalls++
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSONResp(w, 400, map[string]string{"Error": "csr should be passed"})
			return
		}
		f.lastRenew = body
		eid, _ := strconv.ParseInt(fmt.Sprint(body["eid"]), 10, 64)
		old := f.byEID[eid]
		switch {
		case f.renewError == 403:
			writeJSONResp(w, 403, map[string]string{"Error": "User is not authorized to renew this certificate"})
			return
		case f.renewError == 404 || old == nil:
			writeJSONResp(w, 404, map[string]string{"Error": fmt.Sprintf("No enrollment record with eid %d", eid)})
			return
		case f.renewError == 409 || (old.status != "active" && old.status != "expired"):
			writeJSONResp(w, 409, map[string]string{"Error": fmt.Sprintf("certificate is not renewable (status: %s)", old.status)})
			return
		case f.renewError != 0:
			writeJSONResp(w, f.renewError, map[string]string{"Error": "renewal failed"})
			return
		}
		e := f.newEnrollment(w, body)
		if e == nil {
			return
		}
		e.renewedFrom = eid
		writeJSONResp(w, 200, map[string]string{"TaskID": e.taskID})

	case "/enrollment/revoke_cert":
		// Mirrors the backend: only active certificates are revoked, the
		// response is the task ID as plain text, and the record turns revoked
		// once the CA agent completes the task.
		f.revokeCalls++
		eid, _ := strconv.ParseInt(q.Get("eid"), 10, 64)
		e := f.byEID[eid]
		switch {
		case r.Method != http.MethodPost:
			writeJSONResp(w, 405, map[string]string{"message": "Method Not Allowed"})
			return
		case f.revokeError == 403:
			writeJSONResp(w, 403, map[string]string{"Error": "User not authorized"})
			return
		case f.revokeError != 0:
			writeJSONResp(w, f.revokeError, map[string]string{"Error": "Could not revoke certificate, Please check logs for more details."})
			return
		case e == nil || e.status != "active":
			writeJSONResp(w, 404, map[string]string{"Error": fmt.Sprintf("Could not find active certificate with eid %d", eid)})
			return
		}
		f.nextTask++
		rv := &fakeRevocation{taskID: strconv.Itoa(f.nextTask), eid: eid, mode: f.revokeMode}
		f.revocations[rv.taskID] = rv
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(rv.taskID))

	case "/tasks":
		if rv, ok := f.revocations[q.Get("taskID")]; ok {
			rv.polls++
			info, status, details := "PROCESSING", "Task Ready! Assigning an Agent", "Task is created and in queue."
			switch {
			case rv.polls == 1:
				info, status, details = "INITIALIZED", "Task has been created", "Task Created"
			case rv.mode == modeDenied:
				info, status, details = "ERROR", "Revocation failed", "The CA refused the revocation"
			case rv.mode == modeStuck:
			default:
				info, status, details = "OK", "Certificate Revoked", fmt.Sprintf("Certificate with enrollment ID %d", rv.eid)
				f.byEID[rv.eid].status = "revoked"
			}
			writeJSONResp(w, 200, map[string]string{"TaskID": rv.taskID, "status": status, "statusInfo": info, "details": details})
			return
		}
		e, ok := f.byTask[q.Get("taskID")]
		if !ok {
			writeJSONResp(w, 404, map[string]string{"Error": "TaskID not found"})
			return
		}
		e.polls++
		info, status, details := "PROCESSING", "Task Ready! Assigning an Agent", "Task is created and in queue."
		switch {
		case e.polls == 1:
			info, status, details = "INITIALIZED", "Task has been created", "Task Created"
		case e.mode == modeApproval:
			info, status, details = "PENDING", "Pending Approval by Admin", "Certificate has to be approved by: 1 Approver"
			e.status = "requested"
		case e.mode == modeDenied:
			info, status, details = "ERROR", "Denied By Policy Module", "Certificate is denied by policy Module: Wildcard certificates are denied by policy module."
			e.status = "failed"
		case e.mode == modeStuck:
		case e.polls >= 3:
			if e.cert == nil {
				f.issue(e)
			}
			info, status, details = "OK", "Certificate Issued", fmt.Sprintf("Certificate request for enrollment ID %d has been Issued", e.eid)
		}
		// The enrollment record is created once the task leaves INITIALIZED.
		if info != "INITIALIZED" && e.eid == 0 {
			f.nextEID++
			e.eid = f.nextEID
			f.byEID[e.eid] = e
		}
		writeJSONResp(w, 200, map[string]string{"TaskID": e.taskID, "status": status, "statusInfo": info, "details": details})

	case "/enrollment/enrolled_csr_details":
		var e *fakeEnrollment
		if tid := q.Get("taskID"); tid != "" {
			if e = f.byTask[tid]; e == nil || e.eid == 0 {
				writeJSONResp(w, 500, map[string]any{"detail": map[string]any{}, "message": "Internal Server Error"})
				return
			}
		} else {
			eid, _ := strconv.ParseInt(q.Get("eid"), 10, 64)
			if e = f.byEID[eid]; e == nil {
				writeJSONResp(w, 404, map[string]string{"Error": fmt.Sprintf("Enrollment ID %d not found", eid)})
				return
			}
		}
		writeJSONResp(w, 200, map[string]any{
			"EnrollmentID": e.eid, "CertificateAuthority": e.ca, "Template": e.template, "Status": e.status,
			"certAvailable": e.cert != nil, "EmailID": append([]string{}, e.emails...), "commonName": e.csr.Subject.CommonName,
		})

	case "/enrollment/download_cert", "/enrollment/download":
		eid, _ := strconv.ParseInt(q.Get("eid"), 10, 64)
		e := f.byEID[eid]
		if e == nil {
			writeJSONResp(w, 404, map[string]string{"Error": fmt.Sprintf("Enrollment ID %d not found", eid)})
			return
		}
		if e.cert == nil {
			writeJSONResp(w, 400, map[string]string{"Error": "Certificate not available"})
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.URL.Path == "/enrollment/download_cert" {
			_ = pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: e.cert.Raw})
			return
		}
		if q.Get("type") != "p7b" {
			writeJSONResp(w, 400, map[string]string{"Error": "Unsupported certificate type: " + q.Get("type")})
			return
		}
		var der []byte
		for _, c := range []*x509.Certificate{f.root, f.inter, e.cert} {
			der = append(der, c.Raw...)
		}
		p7, _ := pkcs7.DegenerateCertificate(der)
		// Like the real API, label the PKCS#7 bundle as CERTIFICATE.
		_ = pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: p7})

	default:
		writeJSONResp(w, 404, map[string]any{"detail": map[string]any{}, "message": "Not Found"})
	}
}
