// Copyright (c) Encryption Consulting LLC
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/smallstep/pkcs7"
)

// ParseCertificates extracts certificates from a CertSecure download body.
// It accepts PEM (CERTIFICATE and/or PKCS7 blocks), raw DER (certificate or
// PKCS#7), and base64-encoded DER.
func ParseCertificates(body []byte) ([]*x509.Certificate, error) {
	// Binary DER is tried before trimming: its final signature bytes can be
	// whitespace values, and trimming them would corrupt the certificate.
	if certs, err := parseDER(body); err == nil {
		return certs, nil
	}

	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return nil, errors.New("empty certificate body")
	}

	if bytes.Contains(body, []byte("-----BEGIN")) {
		return parsePEMCertificates(body)
	}

	if certs, err := parseDER(body); err == nil {
		return certs, nil
	}

	compact := strings.Join(strings.Fields(string(body)), "")
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding} {
		if der, err := enc.DecodeString(compact); err == nil {
			if certs, err := parseDER(der); err == nil {
				return certs, nil
			}
		}
	}
	return nil, fmt.Errorf("unrecognized certificate format (body starts with %q)", truncate(string(body), 40))
}

func parsePEMCertificates(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "CERTIFICATE":
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				// /enrollment/download?type=p7b sometimes labels a PKCS#7
				// bundle as CERTIFICATE.
				p7, p7err := pkcs7.Parse(block.Bytes)
				if p7err != nil {
					return nil, fmt.Errorf("parsing PEM certificate: %w", err)
				}
				certs = append(certs, p7.Certificates...)
				continue
			}
			certs = append(certs, c)
		case "PKCS7", "CMS":
			p7, err := pkcs7.Parse(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parsing PEM PKCS#7: %w", err)
			}
			certs = append(certs, p7.Certificates...)
		}
	}
	if len(certs) == 0 {
		return nil, errors.New("no certificates found in PEM data")
	}
	return certs, nil
}

func parseDER(der []byte) ([]*x509.Certificate, error) {
	if certs, err := x509.ParseCertificates(der); err == nil && len(certs) > 0 {
		return certs, nil
	}
	p7, err := pkcs7.Parse(der)
	if err != nil {
		return nil, err
	}
	if len(p7.Certificates) == 0 {
		return nil, errors.New("PKCS#7 bundle contains no certificates")
	}
	return p7.Certificates, nil
}

// EncodePEM encodes certificates as concatenated PEM blocks.
func EncodePEM(certs ...*x509.Certificate) string {
	var b strings.Builder
	for _, c := range certs {
		_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	return b.String()
}

// BuildChain returns the issuers of leaf found in pool, ordered issuer first
// (the leaf's issuer, then its issuer, up to the root). The leaf itself is
// excluded. Certificates in pool that are not part of the path are appended
// afterwards in their original order, so nothing the server returned is lost.
func BuildChain(leaf *x509.Certificate, pool []*x509.Certificate) []*x509.Certificate {
	var remaining []*x509.Certificate
	for _, c := range pool {
		if !bytes.Equal(c.Raw, leaf.Raw) && !containsCert(remaining, c) {
			remaining = append(remaining, c)
		}
	}

	var chain []*x509.Certificate
	current := leaf
	for !isSelfSigned(current) {
		idx := -1
		for i, cand := range remaining {
			if issued(cand, current) {
				idx = i
				break
			}
		}
		if idx < 0 {
			break
		}
		next := remaining[idx]
		chain = append(chain, next)
		remaining = append(remaining[:idx], remaining[idx+1:]...)
		current = next
	}
	return append(chain, remaining...)
}

// issued reports whether issuer's subject (and key ID, when both are present)
// matches child's issuer.
func issued(issuer, child *x509.Certificate) bool {
	if !bytes.Equal(issuer.RawSubject, child.RawIssuer) {
		return false
	}
	if len(child.AuthorityKeyId) > 0 && len(issuer.SubjectKeyId) > 0 {
		return bytes.Equal(child.AuthorityKeyId, issuer.SubjectKeyId)
	}
	return true
}

func isSelfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawSubject, c.RawIssuer) &&
		(len(c.AuthorityKeyId) == 0 || len(c.SubjectKeyId) == 0 || bytes.Equal(c.AuthorityKeyId, c.SubjectKeyId))
}

func containsCert(list []*x509.Certificate, c *x509.Certificate) bool {
	for _, x := range list {
		if bytes.Equal(x.Raw, c.Raw) {
			return true
		}
	}
	return false
}

// SerialHex formats a certificate serial as lowercase hex without separators,
// matching the format CertSecure uses (e.g. "3400033ba91e...").
func SerialHex(c *x509.Certificate) string {
	b := c.SerialNumber.Bytes()
	if len(b) == 0 {
		return "00"
	}
	return hex.EncodeToString(b)
}
