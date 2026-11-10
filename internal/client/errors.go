// Copyright (c) Encryption Consulting LLC
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// APIError is a non-2xx response from CertSecure.
type APIError struct {
	Method     string
	Path       string
	StatusCode int
	// Message is the error text extracted from the body ({"Error": ...} or {"message": ...}).
	Message string
	// Body is the raw (truncated) response body.
	Body string
}

func (e *APIError) Error() string {
	msg := e.Message
	if msg == "" {
		msg = e.Body
	}
	if msg == "" {
		msg = http.StatusText(e.StatusCode)
	}
	return fmt.Sprintf("CertSecure %s %s returned HTTP %d: %s", e.Method, e.Path, e.StatusCode, msg)
}

// RequestError is a transport-level failure (connection, TLS, timeout).
type RequestError struct {
	Method string
	Path   string
	Err    error
}

func (e *RequestError) Error() string {
	return fmt.Sprintf("CertSecure %s %s failed: %v", e.Method, e.Path, e.Err)
}

func (e *RequestError) Unwrap() error { return e.Err }

func newAPIError(method, path string, status int, body []byte) *APIError {
	return &APIError{
		Method:     method,
		Path:       path,
		StatusCode: status,
		Message:    extractMessage(body),
		Body:       truncate(strings.TrimSpace(string(body)), 1000),
	}
}

// extractMessage pulls a human-readable error out of the response body.
// CertSecure uses {"Error": "..."} on most endpoints and {"message": "..."}
// for authentication failures.
func extractMessage(body []byte) string {
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		return ""
	}
	for _, key := range []string{"Error", "error", "message", "Message", "detail", "msg"} {
		if s, ok := obj[key].(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

func statusOf(err error) int {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode
	}
	return 0
}

// IsNotFound reports whether err is an HTTP 404 from CertSecure.
func IsNotFound(err error) bool { return statusOf(err) == http.StatusNotFound }

// IsUnauthorized reports whether err is an HTTP 401 from CertSecure.
func IsUnauthorized(err error) bool { return statusOf(err) == http.StatusUnauthorized }

// IsForbidden reports whether err is an HTTP 403 from CertSecure.
func IsForbidden(err error) bool { return statusOf(err) == http.StatusForbidden }

// IsBadRequest reports whether err is an HTTP 400 from CertSecure.
func IsBadRequest(err error) bool { return statusOf(err) == http.StatusBadRequest }

// IsConflict reports whether err is an HTTP 409 from CertSecure.
func IsConflict(err error) bool { return statusOf(err) == http.StatusConflict }

// IsServerError reports whether err is an HTTP 5xx from CertSecure.
func IsServerError(err error) bool { return statusOf(err) >= 500 }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated)"
}
