// Copyright (c) Encryption Consulting LLC
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// checkStatus checks the status of eid in the fake CertSecure.
func checkStatus(f *fakeCertSecure, eid int64, want string) resource.TestCheckFunc {
	return func(*terraform.State) error {
		if got := f.enrollment(eid).status; got != want {
			return fmt.Errorf("enrollment %d status = %q, want %q", eid, got, want)
		}
		return nil
	}
}

const revokeOnDestroy = `
  revoke_on_destroy = true
`

func TestCertificateRevoke_DefaultKeepsCertificate(t *testing.T) {
	f := newFakeCertSecure(t)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories,
		Steps: []resource.TestStep{{
			Config: certificateConfig(f.srv.URL, testCSR(t, "app.example.com"), ""),
			Check:  resource.TestCheckResourceAttr(testAddr, "revoke_on_destroy", "false"),
		}},
		CheckDestroy: resource.ComposeAggregateTestCheckFunc(
			checkStatus(f, 1501, "active"),
			checkCount("revoke_cert", f.revokeCount, 0),
		),
	})
}

func TestCertificateRevoke_OnDestroy(t *testing.T) {
	f := newFakeCertSecure(t)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories,
		Steps: []resource.TestStep{{
			Config: certificateConfig(f.srv.URL, testCSR(t, "app.example.com"), revokeOnDestroy),
			Check:  resource.TestCheckResourceAttr(testAddr, "revoke_on_destroy", "true"),
		}},
		CheckDestroy: resource.ComposeAggregateTestCheckFunc(
			checkStatus(f, 1501, "revoked"),
			checkCount("revoke_cert", f.revokeCount, 1),
		),
	})
}

// Turning revoke_on_destroy on for an existing certificate is a settings change:
// no renewal and no new certificate.
func TestCertificateRevoke_EnableLater(t *testing.T) {
	f := newFakeCertSecure(t)
	csr := testCSR(t, "app.example.com")
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories,
		Steps: []resource.TestStep{
			{Config: certificateConfig(f.srv.URL, csr, "")},
			{
				Config:           certificateConfig(f.srv.URL, csr, revokeOnDestroy),
				ConfigPlanChecks: expectUpdate(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testAddr, "revoke_on_destroy", "true"),
					resource.TestCheckResourceAttr(testAddr, "enrollment_id", "1501"),
					checkCount("enroll_csr", f.enrollCount, 1),
					checkCount("renew_csr", f.renewCount, 0),
					checkCount("revoke_cert", f.revokeCount, 0),
				),
			},
		},
		CheckDestroy: checkStatus(f, 1501, "revoked"),
	})
}

// A certificate that is no longer active is not revoked (CertSecure would
// answer 404), and destroy still succeeds.
func TestCertificateRevoke_NotActive(t *testing.T) {
	for _, status := range []string{"revoked", "expired", "requested"} {
		t.Run(status, func(t *testing.T) {
			f := newFakeCertSecure(t)
			cfg := certificateConfig(f.srv.URL, testCSR(t, "app.example.com"), revokeOnDestroy)
			resource.UnitTest(t, resource.TestCase{
				ProtoV6ProviderFactories: testProviderFactories,
				Steps: []resource.TestStep{
					{Config: cfg},
					{
						PreConfig: func() { f.setStatus(1501, status) },
						Config:    cfg,
						Destroy:   true,
					},
				},
				CheckDestroy: resource.ComposeAggregateTestCheckFunc(
					checkStatus(f, 1501, status),
					checkCount("revoke_cert", f.revokeCount, 0),
				),
			})
		})
	}
}

// A failed revocation keeps the resource in state; the next destroy revokes it.
func TestCertificateRevoke_FailureKeepsState(t *testing.T) {
	cases := map[string]struct {
		setup  func(*fakeCertSecure)
		extra  string
		expect string
	}{
		"task error": {
			setup:  func(f *fakeCertSecure) { f.setRevokeMode(modeDenied) },
			expect: `(?s)revocation failed in CertSecure.*refused the revocation.*task\s+20002.*kept\s+in\s+state`,
		},
		"forbidden": {
			setup:  func(f *fakeCertSecure) { f.setRevokeError(403) },
			expect: `(?s)Not allowed to revoke.*owner of enrollment ID \(eid\)\s+1501`,
		},
		"server error": {
			setup:  func(f *fakeCertSecure) { f.setRevokeError(500) },
			expect: `(?s)Error revoking certificate.*does not revoke it twice`,
		},
		"timeout": {
			setup: func(f *fakeCertSecure) { f.setRevokeMode(modeStuck) },
			extra: `
  timeouts {
    delete = "1s"
  }
`,
			expect: `(?s)Timed out waiting for certificate revocation.*task\s+20002`,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFakeCertSecure(t)
			cfg := certificateConfig(f.srv.URL, testCSR(t, "app.example.com"), revokeOnDestroy+tc.extra)
			resource.UnitTest(t, resource.TestCase{
				ProtoV6ProviderFactories: testProviderFactories,
				Steps: []resource.TestStep{
					{Config: cfg},
					{
						PreConfig:   func() { tc.setup(f) },
						Config:      cfg,
						Destroy:     true,
						ExpectError: regexp.MustCompile(tc.expect),
					},
					{
						PreConfig: func() {
							f.setRevokeError(0)
							f.setRevokeMode(modeIssue)
						},
						Config:  cfg,
						Destroy: true,
					},
				},
				CheckDestroy: checkStatus(f, 1501, "revoked"),
			})
		})
	}
}

// With create_before_destroy, a replacement issues the new certificate first
// and then revokes the old one.
func TestCertificateRevoke_ReplaceCreateBeforeDestroy(t *testing.T) {
	f := newFakeCertSecure(t)
	csr := testCSR(t, "app.example.com")
	cfg := func(template string) string {
		c := certificateConfig(f.srv.URL, csr, revokeOnDestroy+`
  lifecycle {
    create_before_destroy = true
  }
`)
		return strings.Replace(c, `template = "WebServer"`, fmt.Sprintf(`template = %q`, template), 1)
	}
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories,
		Steps: []resource.TestStep{
			{Config: cfg("WebServer")},
			{
				Config: cfg("WebServerV2"),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(testAddr, plancheck.ResourceActionCreateBeforeDestroy),
				}},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testAddr, "enrollment_id", "1502"),
					checkStatus(f, 1501, "revoked"),
					checkStatus(f, 1502, "active"),
					checkCount("revoke_cert", f.revokeCount, 1),
				),
			},
		},
		CheckDestroy: checkStatus(f, 1502, "revoked"),
	})
}
