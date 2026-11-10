// Copyright (c) Encryption Consulting LLC
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"net/url"
	"sort"
)

// AvailableCA is one CA from GET /available_ca.
type AvailableCA struct {
	// Name is the CA name used as the "ca" field of enroll_csr.
	Name string
	// Type is the CA type, e.g. "MSCA", "DIGICERT".
	Type string
	// Connectors are the CertSecure connectors serving this CA.
	Connectors []string
}

// ListAvailableCAs calls GET /available_ca, which returns the CAs the token's
// user may enroll from as {"<type>": {"<ca name>": ["<connector>", ...]}}.
// Results are sorted by type, then name.
func (c *Client) ListAvailableCAs(ctx context.Context) ([]AvailableCA, error) {
	resp, err := c.get(ctx, "/available_ca", nil, true)
	if err != nil {
		return nil, err
	}
	var raw map[string]map[string][]string
	if err := decodeJSON(resp, &raw); err != nil {
		return nil, err
	}
	var out []AvailableCA
	for caType, cas := range raw {
		for name, connectors := range cas {
			conns := append([]string{}, connectors...)
			sort.Strings(conns)
			out = append(out, AvailableCA{Name: name, Type: caType, Connectors: conns})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// TemplateInfo is one template from GET /template/ca.
type TemplateInfo struct {
	FriendlyName      string   `json:"FriendlyName"`
	Description       string   `json:"Description"`
	TemplateOID       string   `json:"TemplateOID"`
	MinKeySize        string   `json:"MinKeySize"`
	ValidityPeriod    string   `json:"ValidityPeriod"`
	RenewalPeriod     string   `json:"RenewalPeriod"`
	KeyUsages         string   `json:"KeyUsages"`
	EnhancedKeyUsages []string `json:"EnhancedKeyUsages"`
	EnrollmentFlags   []string `json:"EnrollmentFlags"`
	CryptoProviders   []string `json:"CryptoProviders"`
}

// GetCATemplates calls GET /template/ca?ca=<ca>, which returns
// {"<ca>": {"configure": bool, "templates": [...]}}, or {} when the CA has no
// templates (or its connector is unavailable).
//
// The entries only carry the template's display (friendly) name; use
// ListTemplateNames for the names accepted by enroll_csr.
func (c *Client) GetCATemplates(ctx context.Context, ca string) ([]TemplateInfo, error) {
	resp, err := c.get(ctx, "/template/ca", url.Values{"ca": {ca}}, true)
	if err != nil {
		return nil, err
	}
	var raw map[string]struct {
		Templates []TemplateInfo `json:"templates"`
	}
	if err := decodeJSON(resp, &raw); err != nil {
		return nil, err
	}
	if entry, ok := raw[ca]; ok {
		return entry.Templates, nil
	}
	if len(raw) == 1 {
		for _, entry := range raw {
			return entry.Templates, nil
		}
	}
	return nil, nil
}

// ListTemplateNames returns the template names accepted by enroll_csr for ca
// (e.g. "WebServer", not the display name "Web Server"), or an empty list when
// CertSecure has no templates for it.
//
// It reads GET /enrollment/templates, which maps every CA to its template
// names. (GET /inventory/templates?ca= answers HTTP 500 for CAs without
// templates, so it is not used.)
func (c *Client) ListTemplateNames(ctx context.Context, ca string) ([]string, error) {
	resp, err := c.get(ctx, "/enrollment/templates", nil, true)
	if err != nil {
		return nil, err
	}
	var byCA map[string][]string
	if err := decodeJSON(resp, &byCA); err != nil {
		return nil, err
	}
	return append([]string{}, byCA[ca]...), nil
}
