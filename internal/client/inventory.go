// Copyright (c) Encryption Consulting LLC
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"net/url"
)

// GetInventoryCertDetails calls GET /inventory/cert_details?ca=<ca>&number=<serial>.
// It returns an *APIError with status 404 when the certificate is not in the
// inventory. The response has many CA-specific fields, so it is returned as a map.
func (c *Client) GetInventoryCertDetails(ctx context.Context, ca, serial string) (map[string]any, error) {
	resp, err := c.get(ctx, "/inventory/cert_details", url.Values{"ca": {ca}, "number": {serial}}, true)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := decodeJSON(resp, &out); err != nil {
		return nil, err
	}
	return out, nil
}
