// Copyright (c) Encryption Consulting LLC
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCertificateDataSource(t *testing.T) {
	f := newFakeCertSecure(t)
	csr := testCSR(t, "app.example.com", "app.example.com")
	config := certificateConfig(f.srv.URL, csr, `  tags = ["terraform", "app"]`) + `
data "certsecure_certificate" "test" {
  enrollment_id = certsecure_certificate.test.enrollment_id
}
`
	const ds, res = "data.certsecure_certificate.test", "certsecure_certificate.test"
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories,
		Steps: []resource.TestStep{{
			Config: config,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr(ds, "id", "1501"),
				resource.TestCheckResourceAttr(ds, "enrollment_id", "1501"),
				resource.TestCheckResourceAttr(ds, "status", "active"),
				resource.TestCheckResourceAttr(ds, "ca_name", "Example Issuing CA"),
				resource.TestCheckResourceAttr(ds, "template", "WebServer"),
				resource.TestCheckResourceAttr(ds, "common_name", "app.example.com"),
				resource.TestCheckResourceAttr(ds, "dns_names.#", "1"),
				resource.TestCheckResourceAttr(ds, "dns_names.0", "app.example.com"),
				resource.TestCheckResourceAttr(ds, "tags.#", "2"),
				resource.TestCheckResourceAttr(ds, "tags.0", "terraform"),
				resource.TestCheckResourceAttrPair(ds, "certificate_pem", res, "certificate_pem"),
				resource.TestCheckResourceAttrPair(ds, "chain_pem", res, "chain_pem"),
				resource.TestCheckResourceAttrPair(ds, "serial_number", res, "serial_number"),
				resource.TestCheckResourceAttrPair(ds, "not_before", res, "not_before"),
				resource.TestCheckResourceAttrPair(ds, "not_after", res, "not_after"),
				checkChain(ds, f),
			),
		}},
	})
}

func TestCertificateDataSource_NotFound(t *testing.T) {
	f := newFakeCertSecure(t)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories,
		Steps: []resource.TestStep{{
			Config: providerBlock(f.srv.URL) + `
data "certsecure_certificate" "test" {
  enrollment_id = 999
}
`,
			ExpectError: regexp.MustCompile(`(?s)Certificate not found.*no\s+enrollment\s+with\s+ID\s+999`),
		}},
	})
}

func TestCertificateDataSource_NotIssued(t *testing.T) {
	f := newFakeCertSecure(t)
	f.setMode(modeApproval)
	csr := testCSR(t, "app.example.com", "app.example.com")
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories,
		Steps: []resource.TestStep{
			{
				// The request waits for approval: enrollment 1501 exists without a certificate.
				Config:      certificateConfig(f.srv.URL, csr, "  timeouts {\n    create = \"2s\"\n  }"),
				ExpectError: regexp.MustCompile(`(?i)approval`),
			},
			{
				Config: providerBlock(f.srv.URL) + `
data "certsecure_certificate" "test" {
  enrollment_id = 1501
}
`,
				ExpectError: regexp.MustCompile(`(?s)Certificate not available.*Enrollment\s+1501\s+has\s+no\s+certificate`),
			},
		},
	})
}

func TestCertificateDataSource_InvalidID(t *testing.T) {
	f := newFakeCertSecure(t)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories,
		Steps: []resource.TestStep{{
			Config: providerBlock(f.srv.URL) + `
data "certsecure_certificate" "test" {
  enrollment_id = 0
}
`,
			ExpectError: regexp.MustCompile(`(?s)enrollment_id.*at least 1`),
		}},
	})
}
