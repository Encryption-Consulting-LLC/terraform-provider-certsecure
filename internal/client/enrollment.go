// Copyright (c) Encryption Consulting LLC
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// SANs groups subject alternative names by type for EnrollCSRRequest.
type SANs struct {
	DNS   []string
	IP    []string
	Email []string
	URI   []string
}

// Entries returns the SANs in the format CertSecure passes to the CA:
// "dns=<name>", "ipaddress=<ip>", "email=<addr>", "url=<uri>".
//
// The swagger documents san_attributes as an object, but the API requires a
// list of these strings; an object is rejected with a generic 400.
func (s SANs) Entries() []string {
	var out []string
	add := func(prefix string, values []string) {
		for _, v := range values {
			out = append(out, prefix+v)
		}
	}
	add("dns=", s.DNS)
	add("ipaddress=", s.IP)
	add("email=", s.Email)
	add("url=", s.URI)
	return out
}

// EnrollCSRRequest is the body of POST /enrollment/enroll_csr.
type EnrollCSRRequest struct {
	CSR      string `json:"csr"`
	CA       string `json:"ca"`
	Template string `json:"template"`
	// Email lists owner/watcher addresses. The API iterates this field, so it
	// must be a list even for a single address.
	Email           []string `json:"email,omitempty"`
	OverrideCSRSANs bool     `json:"override_csr_sans"`
	// SANAttributes holds entries built by SANs.Entries.
	SANAttributes   []string `json:"san_attributes,omitempty"`
	Tags            []string `json:"tags,omitempty"`
	AdditionalNotes string   `json:"additional_notes,omitempty"`
}

// EnrollCSRResponse is the decoded result of POST /enrollment/enroll_csr.
//
// CertSecure processes enrollments asynchronously and responds with only
// {"TaskID": "<id>"}; the enrollment ID is assigned shortly afterwards and is
// found via GetTask / GetEnrollmentDetailsByTaskID.
type EnrollCSRResponse struct {
	// TaskID is the CertSecure task ID.
	TaskID string
	// EnrollmentID is the enrollment ID (eid) if the response included one (current API versions do not).
	EnrollmentID int64
	// HTTPStatus is the HTTP status code.
	HTTPStatus int
	// RawBody is the raw response body, kept so an unrecognized response can be reported.
	RawBody string
}

// EnrollCSR submits a CSR with POST /enrollment/enroll_csr.
//
// This call is NEVER retried: a retry could issue a duplicate certificate.
func (c *Client) EnrollCSR(ctx context.Context, in EnrollCSRRequest) (*EnrollCSRResponse, error) {
	resp, err := c.do(ctx, http.MethodPost, "/enrollment/enroll_csr", nil, in, true)
	if err != nil {
		return nil, err
	}
	return parseEnrollResponse(resp.StatusCode, resp.Body), nil
}

// RenewCSRRequest is the body of POST /enrollment/renew_csr. The embedded
// fields override the old certificate's values. The owner is always inherited
// from the old certificate and cannot be set.
type RenewCSRRequest struct {
	EnrollCSRRequest
	// EID is the enrollment ID of the certificate being renewed.
	EID int64 `json:"eid"`
}

// RenewCSR renews the certificate eid with a caller-supplied CSR via
// POST /enrollment/renew_csr. The CSR may be the same, a new CSR for the same
// key, or a CSR for a new key; CertSecure never generates or stores a key.
// The response is the same asynchronous {"TaskID"} as EnrollCSR.
//
// Errors: 403 (not allowed to renew), 404 (no enrollment record), 409 (not
// renewable: only active and expired certificates renew).
//
// This call is NEVER retried: a retry queues a second renewal.
func (c *Client) RenewCSR(ctx context.Context, in RenewCSRRequest) (*EnrollCSRResponse, error) {
	resp, err := c.do(ctx, http.MethodPost, "/enrollment/renew_csr", nil, in, true)
	if err != nil {
		return nil, err
	}
	return parseEnrollResponse(resp.StatusCode, resp.Body), nil
}

// RevokeCert revokes the certificate eid via POST /enrollment/revoke_cert?eid=<eid>
// and returns the task ID of the revocation, which CertSecure processes
// asynchronously like an enrollment. The response body is the task ID as
// plain text.
//
// Errors: 403 (not the owner, a department PKI admin for the CA, or a global
// admin), 404 (no ACTIVE certificate with this eid: also answered for
// certificates that are pending, expired or already revoked).
//
// This call is NEVER retried: a retry queues a second revocation task.
func (c *Client) RevokeCert(ctx context.Context, eid int64) (string, error) {
	q := url.Values{"eid": {strconv.FormatInt(eid, 10)}}
	resp, err := c.do(ctx, http.MethodPost, "/enrollment/revoke_cert", q, nil, true)
	if err != nil {
		return "", err
	}
	return parseTaskID(resp.Body), nil
}

// parseTaskID reads a task ID returned as plain text ("22041"), as a JSON
// string, or as a JSON object with a TaskID field.
func parseTaskID(body []byte) string {
	s := strings.TrimSpace(string(body))
	var obj map[string]any
	if json.Unmarshal(body, &obj) == nil {
		return toString(lookup(obj, "TaskID", "taskID", "task_id", "taskId"))
	}
	var str string
	if json.Unmarshal(body, &str) == nil {
		return strings.TrimSpace(str)
	}
	if strings.ContainsAny(s, " \t\r\n<>{}") {
		return ""
	}
	return s
}

// parseEnrollResponse decodes the enroll_csr response ({"TaskID": "20795"}).
// Lookup tolerates other spellings in case future API versions change them.
func parseEnrollResponse(status int, body []byte) *EnrollCSRResponse {
	out := &EnrollCSRResponse{HTTPStatus: status, RawBody: truncate(strings.TrimSpace(string(body)), 2000)}
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		return out
	}
	out.TaskID = toString(lookup(obj, "TaskID", "taskID", "task_id", "taskId"))
	out.EnrollmentID = toInt64(lookup(obj, "EnrollmentID", "eid", "enrollment_id", "enrollmentId"))
	return out
}

// EnrollmentDetails is the response of GET /enrollment/enrolled_csr_details.
type EnrollmentDetails struct {
	EnrollmentID         int64    `json:"EnrollmentID"`
	CertificateAuthority string   `json:"CertificateAuthority"`
	Template             string   `json:"Template"`
	Status               string   `json:"Status"`
	CertAvailable        bool     `json:"certAvailable"`
	CommonName           string   `json:"commonName"`
	Owner                string   `json:"owner"`
	EmailID              []string `json:"EmailID"`
	ExpiresOn            string   `json:"ExpiresOn"`
	SANDNSNames          []string `json:"sanDNSNames"`
	SANEmails            []string `json:"sanEmails"`
	SANIPAddresses       []string `json:"sanIPAddresses"`
	Tags                 []string `json:"tags"`
	ThirdPartyCert       bool     `json:"thirdPartyCert"`
}

// GetEnrollmentDetails calls GET /enrollment/enrolled_csr_details?eid=<eid>.
// It returns an *APIError with status 404 when the enrollment does not exist.
func (c *Client) GetEnrollmentDetails(ctx context.Context, eid int64) (*EnrollmentDetails, error) {
	q := url.Values{"eid": {strconv.FormatInt(eid, 10)}}
	resp, err := c.get(ctx, "/enrollment/enrolled_csr_details", q, true)
	if err != nil {
		return nil, err
	}
	var d EnrollmentDetails
	if err := decodeJSON(resp, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// GetEnrollmentDetailsByTaskID calls GET /enrollment/enrolled_csr_details?taskID=<taskID>.
// Before the enrollment record exists (the first moments after enroll_csr),
// and for unknown task IDs, the API answers HTTP 500.
func (c *Client) GetEnrollmentDetailsByTaskID(ctx context.Context, taskID string) (*EnrollmentDetails, error) {
	resp, err := c.get(ctx, "/enrollment/enrolled_csr_details", url.Values{"taskID": {taskID}}, true)
	if err != nil {
		return nil, err
	}
	var d EnrollmentDetails
	if err := decodeJSON(resp, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// DownloadCert calls GET /enrollment/download_cert?eid=<eid> and returns the
// issued (leaf) certificate.
//
// The swagger documents a taskID parameter, but the API requires eid. The
// body is PEM served as text/html; DER and base64 are also accepted.
func (c *Client) DownloadCert(ctx context.Context, eid int64) (*x509.Certificate, error) {
	q := url.Values{"eid": {strconv.FormatInt(eid, 10)}}
	resp, err := c.get(ctx, "/enrollment/download_cert", q, true)
	if err != nil {
		return nil, err
	}
	certs, err := ParseCertificates(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate from /enrollment/download_cert: %w", err)
	}
	return certs[0], nil
}

// DownloadChain calls GET /enrollment/download?eid=<eid>&type=p7b and returns
// every certificate in the PKCS#7 bundle (leaf and CA certificates, in the
// order the server returns them).
func (c *Client) DownloadChain(ctx context.Context, eid int64) ([]*x509.Certificate, error) {
	q := url.Values{"eid": {strconv.FormatInt(eid, 10)}, "type": {"p7b"}}
	resp, err := c.get(ctx, "/enrollment/download", q, true)
	if err != nil {
		return nil, err
	}
	certs, err := ParseCertificates(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("parsing chain from /enrollment/download?type=p7b: %w", err)
	}
	return certs, nil
}

// TrustChainEntry is one element of GET /enrollment/view-trust-chain.
// The endpoint returns metadata only, not certificate bodies.
type TrustChainEntry struct {
	Level        string `json:"level"`
	CommonName   string `json:"common_name"`
	Subject      string `json:"subject"`
	Issuer       string `json:"issuer"`
	Serial       string `json:"serial"`
	SelfSigned   bool   `json:"self_signed"`
	IsCA         bool   `json:"is_ca"`
	Status       string `json:"status"`
	ValidFrom    string `json:"valid_from"`
	ValidTo      string `json:"valid_to"`
	Fingerprints struct {
		SHA256 string `json:"sha256"`
	} `json:"fingerprints"`
}

// GetTrustChain calls GET /enrollment/view-trust-chain?eid=<eid>.
// An unknown eid returns an empty list rather than 404.
func (c *Client) GetTrustChain(ctx context.Context, eid int64) ([]TrustChainEntry, error) {
	q := url.Values{"eid": {strconv.FormatInt(eid, 10)}}
	resp, err := c.get(ctx, "/enrollment/view-trust-chain", q, true)
	if err != nil {
		return nil, err
	}
	var entries []TrustChainEntry
	if err := decodeJSON(resp, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

// lookup returns the first value present in m for any of keys.
func lookup(m map[string]any, keys ...string) any {
	for _, k := range keys {
		if v, ok := m[k]; ok && v != nil {
			return v
		}
	}
	return nil
}

func toInt64(v any) int64 {
	switch t := v.(type) {
	case float64:
		return int64(t)
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(t), 10, 64)
		if err == nil {
			return n
		}
	case json.Number:
		n, err := t.Int64()
		if err == nil {
			return n
		}
	}
	return 0
}

func toString(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case float64:
		return strconv.FormatInt(int64(t), 10)
	case bool:
		return strconv.FormatBool(t)
	}
	return ""
}
