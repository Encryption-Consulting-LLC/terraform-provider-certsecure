// Copyright (c) Encryption Consulting LLC
// SPDX-License-Identifier: Apache-2.0

// Package client is a typed client for the CertSecure Manager REST API.
//
// It has no Terraform dependencies. The CertSecure API mixes identifier
// spellings across endpoints (eid, EnrollmentID, taskID, serialNum, number),
// so each endpoint gets its own explicit method rather than a generic helper.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultTimeout is the per-request timeout used when Config.Timeout is zero.
const DefaultTimeout = 60 * time.Second

// maxResponseBytes caps how much of a response body is read into memory.
const maxResponseBytes = 16 << 20

// LogFunc receives debug log lines. Fields never contain the bearer token.
type LogFunc func(ctx context.Context, msg string, fields map[string]any)

// Config configures a Client.
type Config struct {
	// URL is the base URL of the CertSecure API, e.g. https://certsecure.example.com.
	URL string
	// Token is the API token, without the "Bearer " prefix.
	Token string
	// CABundlePEM optionally holds PEM CA certificates trusted for TLS to CertSecure.
	CABundlePEM string
	// InsecureSkipVerify disables TLS verification. Lab use only.
	InsecureSkipVerify bool
	// Timeout is the per-HTTP-request timeout. Defaults to DefaultTimeout.
	Timeout time.Duration
	// UserAgent is sent with every request.
	UserAgent string
	// Logger optionally receives debug logs of each request.
	Logger LogFunc
	// RetryWait is the base backoff between GET retries. Defaults to 1s.
	RetryWait time.Duration
	// HTTPClient overrides the HTTP client (tests). TLS and timeout settings are ignored when set.
	HTTPClient *http.Client
}

// Client talks to the CertSecure API.
type Client struct {
	baseURL   *url.URL
	token     string
	userAgent string
	http      *http.Client
	logger    LogFunc
	retryWait time.Duration
}

// New validates cfg and returns a Client.
func New(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, errors.New("CertSecure URL is required")
	}
	if strings.TrimSpace(cfg.Token) == "" {
		return nil, errors.New("CertSecure token is required")
	}
	u, err := url.Parse(strings.TrimSpace(cfg.URL))
	if err != nil {
		return nil, fmt.Errorf("invalid CertSecure URL: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("invalid CertSecure URL %q: scheme must be https or http", cfg.URL)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("invalid CertSecure URL %q: missing host", cfg.URL)
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawQuery = ""
	u.Fragment = ""

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		timeout := cfg.Timeout
		if timeout <= 0 {
			timeout = DefaultTimeout
		}
		tlsConfig := &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // Explicit opt-in for lab use.
		}
		if strings.TrimSpace(cfg.CABundlePEM) != "" {
			pool, err := x509.SystemCertPool()
			if err != nil || pool == nil {
				pool = x509.NewCertPool()
			}
			if !pool.AppendCertsFromPEM([]byte(cfg.CABundlePEM)) {
				return nil, errors.New("ca_bundle_pem does not contain any valid PEM certificates")
			}
			tlsConfig.RootCAs = pool
		}
		transport := http.DefaultTransport.(*http.Transport).Clone() //nolint:forcetypeassert // DefaultTransport is always *http.Transport.
		transport.TLSClientConfig = tlsConfig
		httpClient = &http.Client{Timeout: timeout, Transport: transport}
	}

	retryWait := cfg.RetryWait
	if retryWait <= 0 {
		retryWait = time.Second
	}

	return &Client{
		baseURL:   u,
		token:     strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(cfg.Token), "Bearer ")),
		userAgent: cfg.UserAgent,
		http:      httpClient,
		logger:    cfg.Logger,
		retryWait: retryWait,
	}, nil
}

// response is a fully read HTTP response.
type response struct {
	StatusCode  int
	ContentType string
	Body        []byte
}

func (c *Client) endpoint(path string, query url.Values) string {
	u := *c.baseURL
	u.Path = c.baseURL.Path + path
	if len(query) > 0 {
		u.RawQuery = query.Encode()
	}
	return u.String()
}

// do performs exactly one HTTP request. Non-2xx responses return *APIError.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body any, auth bool) (*response, error) {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("encoding request body: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.endpoint(path, query), reqBody)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Accept", "application/json, application/x-pem-file, text/plain, */*")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	if auth {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	start := time.Now()
	resp, err := c.http.Do(req)
	if err != nil {
		c.log(ctx, "CertSecure request failed", map[string]any{"method": method, "path": path, "error": err.Error()})
		return nil, &RequestError{Method: method, Path: path, Err: err}
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, &RequestError{Method: method, Path: path, Err: fmt.Errorf("reading response: %w", err)}
	}

	c.log(ctx, "CertSecure request", map[string]any{
		"method":       method,
		"path":         path,
		"query":        query.Encode(),
		"status":       resp.StatusCode,
		"content_type": resp.Header.Get("Content-Type"),
		"bytes":        len(data),
		"duration_ms":  time.Since(start).Milliseconds(),
	})

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, newAPIError(method, path, resp.StatusCode, data)
	}
	return &response{StatusCode: resp.StatusCode, ContentType: resp.Header.Get("Content-Type"), Body: data}, nil
}

// get performs an idempotent GET, retrying on 5xx and transport errors.
func (c *Client) get(ctx context.Context, path string, query url.Values, auth bool) (*response, error) {
	const attempts = 3
	var lastErr error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			wait := c.retryWait << (i - 1)
			select {
			case <-ctx.Done():
				return nil, errors.Join(ctx.Err(), lastErr)
			case <-time.After(wait):
			}
		}
		resp, err := c.do(ctx, http.MethodGet, path, query, nil, auth)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if !isRetryable(ctx, err) {
			return nil, err
		}
	}
	return nil, lastErr
}

func isRetryable(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return false
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode >= 500
	}
	var reqErr *RequestError
	return errors.As(err, &reqErr)
}

func (c *Client) log(ctx context.Context, msg string, fields map[string]any) {
	if c.logger != nil {
		c.logger(ctx, msg, fields)
	}
}

func decodeJSON(resp *response, v any) error {
	if err := json.Unmarshal(resp.Body, v); err != nil {
		return fmt.Errorf("decoding CertSecure response: %w (body: %s)", err, truncate(string(resp.Body), 300))
	}
	return nil
}
