// Copyright (c) Encryption Consulting LLC
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"fmt"
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

// serialDataSource is a data source that looks up certificate 1501 (serial
// 0x34000005dd in the fake) by serial number once the resource exists.
func serialDataSource(serial, ca string) string {
	return fmt.Sprintf(`
data "certsecure_certificate" "test" {
  serial_number = %q
  ca_name       = %q
  depends_on    = [certsecure_certificate.test]
}
`, serial, ca)
}

func TestCertificateDataSource_BySerial(t *testing.T) {
	f := newFakeCertSecure(t)
	csr := testCSR(t, "app.example.com", "app.example.com")
	const ds, res = "data.certsecure_certificate.test", "certsecure_certificate.test"
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories,
		Steps: []resource.TestStep{
			{
				// The serial number and CA as the resource reports them.
				Config: certificateConfig(f.srv.URL, csr, `  tags = ["terraform"]`) + `
data "certsecure_certificate" "test" {
  serial_number = certsecure_certificate.test.serial_number
  ca_name       = certsecure_certificate.test.ca_name
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(ds, "id", "1501"),
					resource.TestCheckResourceAttr(ds, "enrollment_id", "1501"),
					resource.TestCheckResourceAttr(ds, "serial_number", "34000005dd"),
					resource.TestCheckResourceAttr(ds, "ca_name", "Example Issuing CA"),
					resource.TestCheckResourceAttr(ds, "status", "active"),
					resource.TestCheckResourceAttr(ds, "tags.0", "terraform"),
					resource.TestCheckResourceAttrPair(ds, "certificate_pem", res, "certificate_pem"),
					resource.TestCheckResourceAttrPair(ds, "chain_pem", res, "chain_pem"),
				),
			},
			{
				// Upper case with colons and a leading zero; the CA name in another case.
				Config: certificateConfig(f.srv.URL, csr, `  tags = ["terraform"]`) +
					serialDataSource("00:34:00:00:05:DD", "example issuing ca"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(ds, "enrollment_id", "1501"),
					resource.TestCheckResourceAttr(ds, "serial_number", "00:34:00:00:05:DD"),
					resource.TestCheckResourceAttr(ds, "ca_name", "example issuing ca"),
					resource.TestCheckResourceAttrPair(ds, "certificate_pem", res, "certificate_pem"),
				),
			},
		},
	})
}

func TestCertificateDataSource_BySerialNotFound(t *testing.T) {
	f := newFakeCertSecure(t)
	csr := testCSR(t, "app.example.com", "app.example.com")
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      certificateConfig(f.srv.URL, csr, "") + serialDataSource("0badc0de", "Example Issuing CA"),
				ExpectError: regexp.MustCompile(`(?s)Certificate not found.*serial\s+number\s+0badc0de\s+on\s+CA`),
			},
			{
				// CertSecure matches the serial number on any CA; the provider does not.
				Config:      certificateConfig(f.srv.URL, csr, "") + serialDataSource("34000005dd", "Other Issuing CA"),
				ExpectError: regexp.MustCompile(`(?s)Certificate not found.*serial\s+number\s+34000005dd\s+on\s+CA\s+"Other\s+Issuing\s+CA"`),
			},
			{
				Config:      certificateConfig(f.srv.URL, csr, "") + serialDataSource("34000005dd", "No Such CA"),
				ExpectError: regexp.MustCompile(`(?s)No\s+Such\s+CA\s+-\s+is\s+not\s+a\s+registered\s+CA`),
			},
		},
	})
}

func TestCertificateDataSource_BySerialInventoryOnly(t *testing.T) {
	f := newFakeCertSecure(t)
	f.inventoryOnly = map[string]string{"3400033ba9": "Example Issuing CA"}
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories,
		Steps: []resource.TestStep{{
			Config: providerBlock(f.srv.URL) + `
data "certsecure_certificate" "test" {
  serial_number = "34:00:03:3B:A9"
  ca_name       = "Example Issuing CA"
}
`,
			ExpectError: regexp.MustCompile(`(?s)Certificate not enrolled through CertSecure.*only\s+from\s+the\s+CA\s+inventory`),
		}},
	})
}

func TestCertificateDataSource_LookupValidation(t *testing.T) {
	f := newFakeCertSecure(t)
	cases := map[string]struct{ body, want string }{
		"neither":        {``, `(?s)Missing Attribute Configuration.*enrollment_id,serial_number`},
		"both":           {"enrollment_id = 1\n  serial_number = \"01\"\n  ca_name = \"Example Issuing CA\"", `(?s)Invalid Attribute Combination`},
		"serial no CA":   {`serial_number = "01"`, `(?s)Invalid Attribute Combination.*ca_name`},
		"eid with CA":    {"enrollment_id = 1\n  ca_name = \"Example Issuing CA\"", `(?s)Invalid Attribute Combination`},
		"invalid serial": {"serial_number = \"xyz\"\n  ca_name = \"Example Issuing CA\"", `(?s)serial_number.*hexadecimal\s+serial\s+number`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			resource.UnitTest(t, resource.TestCase{
				ProtoV6ProviderFactories: testProviderFactories,
				Steps: []resource.TestStep{{
					Config:      providerBlock(f.srv.URL) + "\ndata \"certsecure_certificate\" \"test\" {\n  " + tc.body + "\n}\n",
					ExpectError: regexp.MustCompile(tc.want),
				}},
			})
		})
	}
}

func TestNormalizeSerial(t *testing.T) {
	for in, want := range map[string]string{
		"34000005dd": "34000005dd", "34:00:00:05:DD": "34000005dd", "0x00ab": "ab", "AB-CD EF": "abcdef", "00": "0",
	} {
		if got := normalizeSerial(in); got != want {
			t.Errorf("normalizeSerial(%q) = %q, want %q", in, got, want)
		}
	}
}
