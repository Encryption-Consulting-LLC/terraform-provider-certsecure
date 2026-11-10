// Copyright (c) Encryption Consulting LLC
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"context"
	"crypto"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

const testAddr = "certsecure_certificate.test"

// setNow moves the provider's clock for the rest of the test.
func setNow(t *testing.T, at time.Time) {
	t.Helper()
	prev := now
	now = func() time.Time { return at }
	t.Cleanup(func() { now = prev })
}

// expectUpdate checks the plan renews (or updates) the certificate in place.
func expectUpdate() resource.ConfigPlanChecks {
	return resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(testAddr, plancheck.ResourceActionUpdate)}}
}

// priorStateCheck checks attribute values of the state a plan starts from.
type priorStateCheck struct {
	addr  string
	attrs map[string]any
}

func (c priorStateCheck) CheckPlan(_ context.Context, req plancheck.CheckPlanRequest, resp *plancheck.CheckPlanResponse) {
	if req.Plan.PriorState == nil || req.Plan.PriorState.Values == nil {
		resp.Error = fmt.Errorf("plan has no prior state")
		return
	}
	for _, r := range req.Plan.PriorState.Values.RootModule.Resources {
		if r.Address != c.addr {
			continue
		}
		for k, want := range c.attrs {
			if got := r.AttributeValues[k]; fmt.Sprint(got) != fmt.Sprint(want) {
				resp.Error = fmt.Errorf("prior state %s.%s = %v, want %v", c.addr, k, got, want)
				return
			}
		}
		return
	}
	resp.Error = fmt.Errorf("%s not in prior state", c.addr)
}

// checkCertKey checks the test certificate's certificate_pem is for pub.
func checkCertKey(pub crypto.PublicKey) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		cert, err := parseCertificatePEM(s.RootModule().Resources[testAddr].Primary.Attributes["certificate_pem"])
		if err != nil {
			return err
		}
		if !publicKeysEqual(cert.PublicKey, pub) {
			return fmt.Errorf("certificate is not for the expected key")
		}
		return nil
	}
}

func checkCount(name string, got func() int, want int) resource.TestCheckFunc {
	return func(*terraform.State) error {
		if n := got(); n != want {
			return fmt.Errorf("%s called %d times, want %d", name, n, want)
		}
		return nil
	}
}

func TestCertificateRenewal_CSRChange(t *testing.T) {
	f := newFakeCertSecure(t)
	key1, key2 := testKey(t), testKey(t)
	csrA := testCSRForKey(t, key1, "app.example.com", "app.example.com")
	csrNewKey := testCSRForKey(t, key2, "app.example.com", "app.example.com")
	csrNewSANs := testCSRForKey(t, key2, "app.example.com", "app.example.com", "www.example.com")

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: certificateConfig(f.srv.URL, csrA, ""),
				Check:  resource.TestCheckResourceAttr(testAddr, "enrollment_id", "1501"),
			},
			{
				// Key rotation: new key, new CSR.
				Config:           certificateConfig(f.srv.URL, csrNewKey, ""),
				ConfigPlanChecks: expectUpdate(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testAddr, "id", "1502"),
					resource.TestCheckResourceAttr(testAddr, "enrollment_id", "1502"),
					resource.TestCheckResourceAttr(testAddr, "task_id", "20002"),
					resource.TestCheckResourceAttr(testAddr, "status", "active"),
					resource.TestCheckNoResourceAttr(testAddr, "pending_renewal_task_id"),
					checkCertKey(key2.Public()),
					checkCount("enroll_csr", f.enrollCount, 1),
					checkCount("renew_csr", f.renewCount, 1),
					func(*terraform.State) error {
						body := f.lastRenewBody()
						if fmt.Sprint(body["eid"]) != "1501" || !sameCSR(fmt.Sprint(body["csr"]), csrNewKey) {
							return fmt.Errorf("renew_csr body eid=%v, csr matches=%t", body["eid"], sameCSR(fmt.Sprint(body["csr"]), csrNewKey))
						}
						if body["ca"] != "Example Issuing CA" || body["template"] != "WebServer" {
							return fmt.Errorf("renew_csr body ca=%v template=%v", body["ca"], body["template"])
						}
						if old := f.enrollment(1501); old.status != "active" {
							return fmt.Errorf("previous certificate status %q, want active", old.status)
						}
						if n := f.enrollment(1502); n.renewedFrom != 1501 {
							return fmt.Errorf("renewedFrom = %d", n.renewedFrom)
						}
						return nil
					},
				),
			},
			{
				// Same key, new CSR with another SAN.
				Config:           certificateConfig(f.srv.URL, csrNewSANs, ""),
				ConfigPlanChecks: expectUpdate(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testAddr, "enrollment_id", "1503"),
					resource.TestCheckResourceAttr(testAddr, "task_id", "20003"),
					checkCertKey(key2.Public()),
					checkCount("renew_csr", f.renewCount, 2),
					func(s *terraform.State) error {
						if fmt.Sprint(f.lastRenewBody()["eid"]) != "1502" {
							return fmt.Errorf("second renewal was for eid %v, want 1502", f.lastRenewBody()["eid"])
						}
						cert, err := parseCertificatePEM(s.RootModule().Resources[testAddr].Primary.Attributes["certificate_pem"])
						if err != nil {
							return err
						}
						if !slices.Contains(cert.DNSNames, "www.example.com") {
							return fmt.Errorf("renewed certificate SANs %v", cert.DNSNames)
						}
						return nil
					},
				),
			},
			{
				Config:   certificateConfig(f.srv.URL, csrNewSANs, ""),
				PlanOnly: true,
			},
			{
				// Reformatting the same CSR is stored without a renewal.
				Config:           certificateConfig(f.srv.URL, strings.ReplaceAll(csrNewSANs, "\n", "\n\n"), ""),
				ConfigPlanChecks: expectUpdate(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testAddr, "enrollment_id", "1503"),
					checkCount("renew_csr", f.renewCount, 2),
				),
			},
		},
	})
}

func TestCertificateRenewal_EarlyRenewalWindow(t *testing.T) {
	f := newFakeCertSecure(t)
	setNow(t, time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))
	key := testKey(t)
	csr := testCSRForKey(t, key, "app.example.com", "app.example.com")
	renewAt := time.Date(2028, 10, 20, 12, 0, 0, 0, time.UTC) // within 24h of not_after 2028-10-21T01:39:03Z

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: certificateConfig(f.srv.URL, csr, "  early_renewal_hours = 720"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testAddr, "enrollment_id", "1501"),
					resource.TestCheckResourceAttr(testAddr, "early_renewal_hours", "720"),
				),
			},
			{
				// Outside the window: nothing to do.
				Config:   certificateConfig(f.srv.URL, csr, "  early_renewal_hours = 720"),
				PlanOnly: true,
			},
			{
				// Changing only the window makes no API calls.
				Config:           certificateConfig(f.srv.URL, csr, "  early_renewal_hours = 24"),
				ConfigPlanChecks: expectUpdate(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testAddr, "enrollment_id", "1501"),
					resource.TestCheckResourceAttr(testAddr, "early_renewal_hours", "24"),
					checkCount("enroll_csr", f.enrollCount, 1),
					checkCount("renew_csr", f.renewCount, 0),
				),
			},
			{
				// Inside the window: renewed in place with the same CSR.
				PreConfig: func() {
					setNow(t, renewAt)
					f.setIssueAt(renewAt)
				},
				Config:           certificateConfig(f.srv.URL, csr, "  early_renewal_hours = 24"),
				ConfigPlanChecks: expectUpdate(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testAddr, "enrollment_id", "1502"),
					resource.TestCheckResourceAttr(testAddr, "not_before", "2028-10-20T12:00:00Z"),
					checkCertKey(key.Public()),
					checkCount("renew_csr", f.renewCount, 1),
					func(*terraform.State) error {
						if !sameCSR(fmt.Sprint(f.lastRenewBody()["csr"]), csr) {
							return fmt.Errorf("renewal did not use the configured CSR")
						}
						return nil
					},
				),
			},
			{
				Config:   certificateConfig(f.srv.URL, csr, "  early_renewal_hours = 24"),
				PlanOnly: true,
			},
		},
	})
}

func TestCertificateRenewal_PendingApprovalResumes(t *testing.T) {
	f := newFakeCertSecure(t)
	key2 := testKey(t)
	csrA := testCSR(t, "app.example.com")
	csrB := testCSRForKey(t, key2, "app.example.com")
	csrC := testCSR(t, "app.example.com")
	pending := regexp.MustCompile(`(?s)Certificate renewal requires approval.*task\s+ID\s+20002.*resumes\s+this\s+renewal`)
	renewedOnce := func() {
		if n := f.renewCount(); n != 1 {
			t.Fatalf("renew_csr called %d times, want 1", n)
		}
	}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories,
		Steps: []resource.TestStep{
			{Config: certificateConfig(f.srv.URL, csrA, "")},
			{
				PreConfig:   func() { f.setMode(modeApproval) },
				Config:      certificateConfig(f.srv.URL, csrB, ""),
				ExpectError: pending,
			},
			{
				// The previous certificate stays in state with the pending task.
				Config:             certificateConfig(f.srv.URL, csrB, ""),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
				ConfigPlanChecks: resource.ConfigPlanChecks{PostApplyPreRefresh: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(testAddr, plancheck.ResourceActionUpdate),
					priorStateCheck{testAddr, map[string]any{"enrollment_id": 1501, "pending_renewal_task_id": "20002", "csr_pem": strings.TrimSpace(csrA) + "\n"}},
				}},
			},
			{
				// Still waiting: the apply resumes and does not submit again.
				Config:      certificateConfig(f.srv.URL, csrB, ""),
				ExpectError: pending,
			},
			{
				// A different CSR while the renewal is pending is refused.
				PreConfig:   renewedOnce,
				Config:      certificateConfig(f.srv.URL, csrC, ""),
				ExpectError: regexp.MustCompile(`A renewal for a different CSR is still pending`),
			},
			{
				// Approved in CertSecure: the next apply completes the same renewal.
				PreConfig: func() {
					renewedOnce()
					f.setTaskMode("20002", modeIssue)
				},
				Config: certificateConfig(f.srv.URL, csrB, ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testAddr, "enrollment_id", "1502"),
					resource.TestCheckResourceAttr(testAddr, "task_id", "20002"),
					resource.TestCheckNoResourceAttr(testAddr, "pending_renewal_task_id"),
					checkCertKey(key2.Public()),
					checkCount("renew_csr", f.renewCount, 1),
				),
			},
		},
	})
}

func TestCertificateRenewal_DeniedSubmitsAgain(t *testing.T) {
	f := newFakeCertSecure(t)
	csrA := testCSR(t, "app.example.com")
	csrB := testCSR(t, "app.example.com")

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories,
		Steps: []resource.TestStep{
			{Config: certificateConfig(f.srv.URL, csrA, "")},
			{
				PreConfig:   func() { f.setMode(modeDenied) },
				Config:      certificateConfig(f.srv.URL, csrB, ""),
				ExpectError: regexp.MustCompile(`(?s)Certificate request failed in CertSecure.*Denied By Policy Module.*submits\s+a\s+new\s+renewal`),
			},
			{
				Config:             certificateConfig(f.srv.URL, csrB, ""),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
				ConfigPlanChecks: resource.ConfigPlanChecks{PostApplyPreRefresh: []plancheck.PlanCheck{
					priorStateCheck{testAddr, map[string]any{"enrollment_id": 1501, "pending_renewal_task_id": nil}},
				}},
			},
			{
				PreConfig: func() { f.setMode(modeIssue) },
				Config:    certificateConfig(f.srv.URL, csrB, ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testAddr, "enrollment_id", "1503"),
					checkCount("renew_csr", f.renewCount, 2),
				),
			},
		},
	})
}

func TestCertificateRenewal_TimeoutResumes(t *testing.T) {
	f := newFakeCertSecure(t)
	csrA := testCSR(t, "app.example.com")
	csrB := testCSR(t, "app.example.com")
	timeouts := `
  timeouts {
    update = "2s"
  }
`
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories,
		Steps: []resource.TestStep{
			{Config: certificateConfig(f.srv.URL, csrA, timeouts)},
			{
				PreConfig:   func() { f.setMode(modeStuck) },
				Config:      certificateConfig(f.srv.URL, csrB, timeouts),
				ExpectError: regexp.MustCompile(`(?s)Timed out waiting for certificate renewal.*resumes\s+this\s+renewal`),
			},
			{
				PreConfig: func() { f.setTaskMode("20002", modeIssue) },
				Config:    certificateConfig(f.srv.URL, csrB, timeouts),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testAddr, "enrollment_id", "1502"),
					resource.TestCheckNoResourceAttr(testAddr, "pending_renewal_task_id"),
					checkCount("renew_csr", f.renewCount, 1),
				),
			},
		},
	})
}

func TestCertificateRenewal_SubmitErrors(t *testing.T) {
	cases := map[int]string{
		404: `(?s)Certificate no longer exists in CertSecure.*eid\)\s+1501`,
		409: `(?s)Certificate is not renewable.*status:\s+active`,
		403: `(?s)Not allowed to renew this certificate.*Renew\s+Inventory\s+Certificates`,
	}
	for status, want := range cases {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			f := newFakeCertSecure(t)
			csrA := testCSR(t, "app.example.com")
			csrB := testCSR(t, "app.example.com")
			resource.UnitTest(t, resource.TestCase{
				ProtoV6ProviderFactories: testProviderFactories,
				Steps: []resource.TestStep{
					{Config: certificateConfig(f.srv.URL, csrA, "")},
					{
						PreConfig:   func() { f.setRenewError(status) },
						Config:      certificateConfig(f.srv.URL, csrB, ""),
						ExpectError: regexp.MustCompile(want),
					},
					{
						// State is unchanged: same certificate, nothing pending.
						Config:             certificateConfig(f.srv.URL, csrB, ""),
						PlanOnly:           true,
						ExpectNonEmptyPlan: true,
						ConfigPlanChecks: resource.ConfigPlanChecks{PostApplyPreRefresh: []plancheck.PlanCheck{
							priorStateCheck{testAddr, map[string]any{"enrollment_id": 1501, "task_id": "20001", "pending_renewal_task_id": nil}},
						}},
					},
				},
			})
		})
	}
}

func TestCertificateRenewal_OtherChangesReplace(t *testing.T) {
	f := newFakeCertSecure(t)
	csr := testCSR(t, "app.example.com")
	cfg := func(template string) string {
		return strings.Replace(certificateConfig(f.srv.URL, csr, ""), `template = "WebServer"`, fmt.Sprintf(`template = %q`, template), 1)
	}
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories,
		Steps: []resource.TestStep{
			{Config: cfg("WebServer")},
			{
				Config: cfg("WebServerV2"),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(testAddr, plancheck.ResourceActionDestroyBeforeCreate),
				}},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testAddr, "enrollment_id", "1502"),
					checkCount("enroll_csr", f.enrollCount, 2),
					checkCount("renew_csr", f.renewCount, 0),
				),
			},
		},
	})
}

func TestCertificateRenewal_Import(t *testing.T) {
	importConfig := func(url, seedCSR, csr string) string {
		return certificateConfig(url, seedCSR, "") + fmt.Sprintf(`
import {
  to = certsecure_certificate.imported
  id = "1501"
}

resource "certsecure_certificate" "imported" {
  csr_pem  = <<-EOT
%s
  EOT
  ca_name  = "Example Issuing CA"
  template = "WebServer"
}
`, strings.TrimSpace(csr))
	}
	cases := map[string]struct {
		sameKey bool
		eid     string
		renews  int
	}{
		"same key adopts the CSR":   {true, "1501", 0},
		"different key renews once": {false, "1502", 1},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFakeCertSecure(t)
			key := testKey(t)
			seed := testCSRForKey(t, key, "app.example.com")
			csr := testCSR(t, "app.example.com")
			if tc.sameKey {
				csr = testCSRForKey(t, key, "app.example.com", "app.example.com")
			}
			resource.UnitTest(t, resource.TestCase{
				ProtoV6ProviderFactories: testProviderFactories,
				Steps: []resource.TestStep{
					{Config: certificateConfig(f.srv.URL, seed, "")},
					{
						Config: importConfig(f.srv.URL, seed, csr),
						Check: resource.ComposeAggregateTestCheckFunc(
							resource.TestCheckResourceAttr("certsecure_certificate.imported", "enrollment_id", tc.eid),
							resource.TestCheckResourceAttrSet("certsecure_certificate.imported", "csr_pem"),
							checkCount("renew_csr", f.renewCount, tc.renews),
						),
					},
				},
			})
		})
	}
}

// Unit tests for the plan-time helpers.

func TestRenewalReasonAndWindowWarning(t *testing.T) {
	setNow(t, time.Date(2028, 10, 1, 0, 0, 0, 0, time.UTC))
	key := testKey(t)
	csr := testCSRForKey(t, key, "a.example.com")
	model := func(hours int64) *certificateModel {
		return &certificateModel{
			CSRPEM:               types.StringValue(csr),
			NotBefore:            types.StringValue("2026-10-22T01:39:03Z"),
			NotAfter:             types.StringValue("2028-10-21T01:39:03Z"),
			EarlyRenewalHours:    types.Int64Value(hours),
			PendingRenewalTaskID: types.StringNull(),
		}
	}
	cases := []struct {
		name        string
		state, plan *certificateModel
		reason      bool
		warn        bool
	}{
		{name: "disabled", state: model(0), plan: model(0)},
		{name: "outside window", state: model(24), plan: model(24)},
		{name: "inside window", state: model(24 * 30), plan: model(24 * 30), reason: true},
		{name: "window covers lifetime", state: model(24 * 731), plan: model(24 * 731), reason: true, warn: true},
		{name: "pending renewal", state: func() *certificateModel {
			m := model(0)
			m.PendingRenewalTaskID = types.StringValue("20002")
			return m
		}(), plan: model(0), reason: true},
		{name: "unknown csr", state: model(0), plan: func() *certificateModel { m := model(0); m.CSRPEM = types.StringUnknown(); return m }(), reason: true},
		{name: "reformatted csr", state: model(0), plan: func() *certificateModel {
			m := model(0)
			m.CSRPEM = types.StringValue("\n" + strings.ReplaceAll(csr, "\n", "\r\n"))
			return m
		}()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := renewalReason(tc.state, tc.plan); (got != "") != tc.reason {
				t.Errorf("renewalReason = %q, want renewal %t", got, tc.reason)
			}
			if got := renewalWindowWarning(tc.state, tc.plan); (got != "") != tc.warn {
				t.Errorf("renewalWindowWarning = %q, want warning %t", got, tc.warn)
			}
		})
	}
}
