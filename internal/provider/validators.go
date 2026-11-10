// Copyright (c) Encryption Consulting LLC
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// parseCSR decodes a PEM certificate signing request and verifies its signature.
func parseCSR(s string) (*x509.CertificateRequest, error) {
	block, rest := pem.Decode([]byte(strings.TrimSpace(s)))
	if block == nil {
		return nil, errors.New("value is not PEM encoded")
	}
	if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("PEM block type is %q, expected \"CERTIFICATE REQUEST\"", block.Type)
	}
	if len(strings.TrimSpace(string(rest))) > 0 {
		return nil, errors.New("value contains data after the CSR; provide exactly one PEM CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature is invalid: %w", err)
	}
	return csr, nil
}

// csrValidator rejects values that are not a valid PEM CSR.
type csrValidator struct{}

func (csrValidator) Description(context.Context) string {
	return "value must be a PEM-encoded PKCS#10 certificate signing request"
}

func (v csrValidator) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }

func (v csrValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if _, err := parseCSR(req.ConfigValue.ValueString()); err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid CSR", err.Error())
	}
}

// sanKind identifies a SAN list for sanValidator.
type sanKind int

const (
	sanDNS sanKind = iota
	sanIP
	sanEmail
	sanURI
)

// sanUnsafeChars are characters CertSecure uses as separators when passing SANs
// to the CA ("dns=a&dns=b", comma-separated lists, quoted command arguments).
const sanUnsafeChars = "&,;\"'`<>|\\ \t\r\n"

// sanValidator validates the entries of one subject_alternative_names list.
type sanValidator struct{ kind sanKind }

func (v sanValidator) Description(context.Context) string {
	switch v.kind {
	case sanIP:
		return "each entry must be a valid IPv4 or IPv6 address"
	case sanEmail:
		return "each entry must be a valid email address"
	case sanURI:
		return "each entry must be an absolute URI with a scheme"
	default:
		return "each entry must be a DNS name"
	}
}

func (v sanValidator) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }

func (v sanValidator) ValidateList(ctx context.Context, req validator.ListRequest, resp *validator.ListResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	for i, el := range req.ConfigValue.Elements() {
		s, ok := el.(types.String)
		if !ok || s.IsNull() || s.IsUnknown() {
			continue
		}
		if err := v.check(s.ValueString()); err != nil {
			resp.Diagnostics.AddAttributeError(req.Path.AtListIndex(i), "Invalid subject alternative name", err.Error())
		}
	}
}

func (v sanValidator) check(s string) error {
	if s == "" {
		return errors.New("entry must not be empty")
	}
	if strings.ContainsAny(s, sanUnsafeChars) {
		return fmt.Errorf("%q contains a character that is not allowed in a SAN entry (whitespace or one of & , ; \" ' ` < > | \\)", s)
	}
	switch v.kind {
	case sanIP:
		if net.ParseIP(s) == nil {
			return fmt.Errorf("%q is not a valid IP address", s)
		}
	case sanEmail:
		if a, err := mail.ParseAddress(s); err != nil || a.Address != s {
			return fmt.Errorf("%q is not a valid email address", s)
		}
	case sanURI:
		u, err := url.Parse(s)
		if err != nil || u.Scheme == "" || (u.Host == "" && u.Opaque == "") {
			return fmt.Errorf("%q is not an absolute URI (expected e.g. https://app.example.com or spiffe://example.com/app)", s)
		}
	default:
		name := strings.TrimPrefix(s, "*.")
		if len(name) > 253 || strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") || strings.Contains(name, "..") {
			return fmt.Errorf("%q is not a valid DNS name", s)
		}
		for _, label := range strings.Split(name, ".") {
			if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
				return fmt.Errorf("%q is not a valid DNS name", s)
			}
			for _, r := range label {
				if !isDNSLabelRune(r) {
					return fmt.Errorf("%q is not a valid DNS name", s)
				}
			}
		}
	}
	return nil
}

func isDNSLabelRune(r rune) bool {
	return r == '-' || r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}

// emailValidator checks a single email address.
type emailValidator struct{}

func (emailValidator) Description(context.Context) string {
	return "value must be a valid email address"
}

func (v emailValidator) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }

func (v emailValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	s := req.ConfigValue.ValueString()
	if a, err := mail.ParseAddress(s); err != nil || a.Address != s {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid email address", fmt.Sprintf("%q is not a valid email address.", s))
	}
}

// overrideRequiresSANs rejects override_csr_sans = true without any
// subject_alternative_names entries: overriding the CSR's SANs with nothing
// would issue a certificate without SANs.
type overrideRequiresSANs struct{}

var _ resource.ConfigValidator = overrideRequiresSANs{}

func (overrideRequiresSANs) Description(context.Context) string {
	return "override_csr_sans = true requires a subject_alternative_names block with at least one entry"
}

func (v overrideRequiresSANs) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v overrideRequiresSANs) ValidateResource(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var override types.Bool
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("override_csr_sans"), &override)...)
	if resp.Diagnostics.HasError() || override.IsNull() || override.IsUnknown() || !override.ValueBool() {
		return
	}

	var sans *sanModel
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("subject_alternative_names"), &sans)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if sans == nil {
		resp.Diagnostics.AddAttributeError(path.Root("override_csr_sans"), "Missing subject_alternative_names",
			"override_csr_sans = true replaces the SANs in the CSR with those in subject_alternative_names, "+
				"so a subject_alternative_names block is required.")
		return
	}
	for _, l := range []types.List{sans.DNS, sans.IP, sans.Email, sans.URI} {
		if l.IsUnknown() || len(l.Elements()) > 0 {
			return
		}
	}
	resp.Diagnostics.AddAttributeError(path.Root("subject_alternative_names"), "Empty subject_alternative_names",
		"override_csr_sans = true requires at least one entry in subject_alternative_names.")
}
