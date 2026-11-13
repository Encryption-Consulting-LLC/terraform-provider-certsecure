// Copyright (c) Encryption Consulting LLC
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func certificateConfig(url, csr, extra string) string {
	return providerBlock(url) + fmt.Sprintf(`
resource "certsecure_certificate" "test" {
  csr_pem  = <<-EOT
%s
  EOT
  ca_name  = "Example Issuing CA"
  template = "WebServer"
%s
}
`, strings.TrimSpace(csr), extra)
}

func TestCertificateResource_Lifecycle(t *testing.T) {
	f := newFakeCertSecure(t)
	csr := testCSR(t, "app.example.com", "app.example.com")
	extra := `
  owner_email = "owner@example.com"
  tags        = ["terraform", "app"]
  notes       = "managed by terraform"
  subject_alternative_names {
    dns = ["app.example.com", "www.example.com"]
    ip  = ["192.0.2.10"]
    uri = ["spiffe://example.com/app"]
  }
`
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: certificateConfig(f.srv.URL, csr, extra),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("certsecure_certificate.test", "id", "1501"),
					resource.TestCheckResourceAttr("certsecure_certificate.test", "enrollment_id", "1501"),
					resource.TestCheckResourceAttr("certsecure_certificate.test", "task_id", "20001"),
					resource.TestCheckResourceAttr("certsecure_certificate.test", "status", "active"),
					resource.TestCheckResourceAttr("certsecure_certificate.test", "override_csr_sans", "false"),
					resource.TestCheckResourceAttr("certsecure_certificate.test", "serial_number", "34000005dd"),
					resource.TestCheckResourceAttr("certsecure_certificate.test", "not_before", "2026-10-22T01:39:03Z"),
					resource.TestCheckResourceAttr("certsecure_certificate.test", "not_after", "2028-10-21T01:39:03Z"),
					checkChain("certsecure_certificate.test", f),
					func(*terraform.State) error {
						body := f.lastEnrollBody()
						want := `[dns=app.example.com dns=www.example.com ipaddress=192.0.2.10 url=spiffe://example.com/app]`
						if got := fmt.Sprint(body["san_attributes"]); got != want {
							return fmt.Errorf("san_attributes = %s, want %s", got, want)
						}
						if got := fmt.Sprint(body["email"]); got != "[owner@example.com]" {
							return fmt.Errorf("email = %s", got)
						}
						if body["additional_notes"] != "managed by terraform" || fmt.Sprint(body["tags"]) != "[terraform app]" {
							return fmt.Errorf("unexpected body %v", body)
						}
						return nil
					},
				),
			},
			{
				ResourceName:      "certsecure_certificate.test",
				ImportState:       true,
				ImportStateId:     "1501",
				ImportStateVerify: true,
				// Not recoverable from CertSecure.
				ImportStateVerifyIgnore: []string{"csr_pem", "owner_email", "tags", "notes", "subject_alternative_names", "task_id", "timeouts"},
			},
		},
	})
	if n := f.enrollCount(); n != 1 {
		t.Fatalf("enroll_csr called %d times, want 1", n)
	}
}

// checkChain verifies certificate_pem holds the leaf and chain_pem holds the
// issuing CA then the root (issuer first), even though the server returns the
// bundle root first.
func checkChain(name string, f *fakeCertSecure) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs := s.RootModule().Resources[name].Primary.Attributes
		var chain []*x509.Certificate
		rest := []byte(rs["chain_pem"])
		for {
			var b *pem.Block
			b, rest = pem.Decode(rest)
			if b == nil {
				break
			}
			c, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				return err
			}
			chain = append(chain, c)
		}
		if len(chain) != 2 || !chain[0].Equal(f.inter) || !chain[1].Equal(f.root) {
			return fmt.Errorf("chain_pem has %d certs in wrong order", len(chain))
		}
		b, _ := pem.Decode([]byte(rs["certificate_pem"]))
		leaf, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return err
		}
		if leaf.Subject.CommonName != "app.example.com" {
			return fmt.Errorf("unexpected leaf %s", leaf.Subject)
		}
		return nil
	}
}

func TestCertificateResource_MinimalNoReplanAndRemovedOutsideTerraform(t *testing.T) {
	f := newFakeCertSecure(t)
	csr := testCSR(t, "min.example.com")
	cfg := certificateConfig(f.srv.URL, csr, "")
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("certsecure_certificate.test", "status", "active"),
					func(*terraform.State) error {
						body := f.lastEnrollBody()
						for _, k := range []string{"san_attributes", "email", "tags", "additional_notes"} {
							if _, ok := body[k]; ok {
								return fmt.Errorf("%s should not be sent", k)
							}
						}
						return nil
					},
				),
			},
			{
				// No changes on a second plan.
				Config:   cfg,
				PlanOnly: true,
			},
			{
				// Deleted in CertSecure: refresh removes it, so Terraform plans a new one.
				PreConfig:          func() { f.deleteEnrollment(1501) },
				Config:             cfg,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestCertificateResource_PendingApproval(t *testing.T) {
	f := newFakeCertSecure(t)
	f.setMode(modeApproval)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories,
		Steps: []resource.TestStep{{
			Config:      certificateConfig(f.srv.URL, testCSR(t, "pending.example.com"), ""),
			ExpectError: regexp.MustCompile(`(?s)requires approval.*enrollment ID \(eid\)\s+1501,\s+task\s+ID\s+20001`),
		}},
	})
	if n := f.enrollCount(); n != 1 {
		t.Fatalf("enroll_csr called %d times, want 1", n)
	}
}

func TestCertificateResource_Denied(t *testing.T) {
	f := newFakeCertSecure(t)
	f.setMode(modeDenied)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories,
		Steps: []resource.TestStep{{
			Config:      certificateConfig(f.srv.URL, testCSR(t, "denied.example.com"), ""),
			ExpectError: regexp.MustCompile(`(?s)Certificate request failed.*Denied By Policy Module.*enrollment ID \(eid\)\s+1501,\s+task\s+ID\s+20001`),
		}},
	})
}

func TestCertificateResource_Timeout(t *testing.T) {
	f := newFakeCertSecure(t)
	f.setMode(modeStuck)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories,
		Steps: []resource.TestStep{{
			Config: certificateConfig(f.srv.URL, testCSR(t, "slow.example.com"), `
  timeouts {
    create = "2s"
  }
`),
			ExpectError: regexp.MustCompile(`(?s)Timed out waiting for certificate.*enrollment ID \(eid\)\s+1501,\s+task\s+ID\s+20001`),
		}},
	})
	if n := f.enrollCount(); n != 1 {
		t.Fatalf("enroll_csr called %d times, want 1", n)
	}
}

func TestCertificateResource_KeyMismatch(t *testing.T) {
	f := newFakeCertSecure(t)
	f.setMode(modeWrongKey)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories,
		Steps: []resource.TestStep{{
			Config:      certificateConfig(f.srv.URL, testCSR(t, "wrong.example.com"), ""),
			ExpectError: regexp.MustCompile(`does not match the CSR`),
		}},
	})
}

func TestCertificateResource_PlanValidation(t *testing.T) {
	f := newFakeCertSecure(t)
	csr := testCSR(t, "v.example.com")
	cases := map[string]struct {
		csr, extra string
		err        string
	}{
		"invalid csr":        {"not a csr", "", `Invalid CSR`},
		"certificate pem":    {"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----", "", `Invalid CSR`},
		"override no sans":   {csr, `override_csr_sans = true`, `Missing subject_alternative_names`},
		"override empty":     {csr, "override_csr_sans = true\n  subject_alternative_names {\n    dns = []\n  }", `Empty subject_alternative_names`},
		"bad ip":             {csr, "subject_alternative_names {\n    ip = [\"300.1.1.1\"]\n  }", `not a valid IP address`},
		"bad uri":            {csr, "subject_alternative_names {\n    uri = [\"not-a-uri\"]\n  }", `not an absolute URI`},
		"injection in dns":   {csr, "subject_alternative_names {\n    dns = [\"a.example.com&dns=evil.com\"]\n  }", `(?s)not allowed in a\s+SAN entry`},
		"bad owner email":    {csr, `owner_email = "nope"`, `not a valid email address`},
		"duplicate dns":      {csr, "subject_alternative_names {\n    dns = [\"a.example.com\", \"a.example.com\"]\n  }", `(?i)duplicate`},
		"bad create timeout": {csr, "timeouts {\n    create = \"soon\"\n  }", `(?i)invalid`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			resource.UnitTest(t, resource.TestCase{
				ProtoV6ProviderFactories: testProviderFactories,
				Steps: []resource.TestStep{{
					Config:      certificateConfig(f.srv.URL, tc.csr, "  "+tc.extra),
					PlanOnly:    true,
					ExpectError: regexp.MustCompile(tc.err),
				}},
			})
		})
	}
	if n := f.enrollCount(); n != 0 {
		t.Fatalf("enroll_csr called %d times during plan-only tests", n)
	}
}

// After import, the first apply records revoke_on_destroy, wait_for_approval,
// early_renewal_hours (outside the window) and the CSR for the same key without
// issuing or renewing.
func TestCertificateResource_ImportThenApplySettings(t *testing.T) {
	f := newFakeCertSecure(t)
	csr := testCSR(t, "import.example.com")
	settings := "  revoke_on_destroy   = true\n  wait_for_approval   = true\n  early_renewal_hours = 24\n"
	// Issue the certificate; destroy only removes it from state (the default).
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories,
		Steps:                    []resource.TestStep{{Config: certificateConfig(f.srv.URL, csr, "")}},
	})
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:             certificateConfig(f.srv.URL, csr, ""),
				ResourceName:       "certsecure_certificate.test",
				ImportState:        true,
				ImportStateId:      "1501",
				ImportStatePersist: true,
			},
			{
				Config: certificateConfig(f.srv.URL, csr, settings),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("certsecure_certificate.test", "enrollment_id", "1501"),
					resource.TestCheckResourceAttr("certsecure_certificate.test", "revoke_on_destroy", "true"),
					resource.TestCheckResourceAttr("certsecure_certificate.test", "wait_for_approval", "true"),
					resource.TestCheckResourceAttr("certsecure_certificate.test", "early_renewal_hours", "24"),
				),
			},
			{
				Config:   certificateConfig(f.srv.URL, csr, settings),
				PlanOnly: true,
			},
		},
	})
	if n := f.enrollCount(); n != 1 {
		t.Fatalf("enroll_csr called %d times, want 1", n)
	}
	if n := f.renewCount(); n != 0 {
		t.Fatalf("renew_csr called %d times, want 0", n)
	}
}

func TestCertificateResource_ImportInvalidID(t *testing.T) {
	f := newFakeCertSecure(t)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories,
		Steps: []resource.TestStep{{
			Config:        certificateConfig(f.srv.URL, testCSR(t, "i.example.com"), ""),
			ResourceName:  "certsecure_certificate.test",
			ImportState:   true,
			ImportStateId: "abc",
			ExpectError:   regexp.MustCompile(`Invalid import ID`),
		}},
	})
}
