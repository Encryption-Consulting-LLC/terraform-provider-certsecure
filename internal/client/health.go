// Copyright (c) Encryption Consulting LLC
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
)

// VersionInfo is the response of GET /version.
type VersionInfo struct {
	Backend  string `json:"Backend"`
	Frontend string `json:"Frontend"`
	Mode     string `json:"mode"`
}

// Check calls the unauthenticated reachability endpoint GET /check.
func (c *Client) Check(ctx context.Context) error {
	_, err := c.get(ctx, "/check", nil, false)
	return err
}

// Version calls the unauthenticated GET /version.
func (c *Client) Version(ctx context.Context) (*VersionInfo, error) {
	resp, err := c.get(ctx, "/version", nil, false)
	if err != nil {
		return nil, err
	}
	var v VersionInfo
	if err := decodeJSON(resp, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// CheckToken validates the bearer token with GET /check_token.
// It returns an *APIError with status 401 when the token is invalid or expired.
func (c *Client) CheckToken(ctx context.Context) error {
	_, err := c.get(ctx, "/check_token", nil, true)
	return err
}
