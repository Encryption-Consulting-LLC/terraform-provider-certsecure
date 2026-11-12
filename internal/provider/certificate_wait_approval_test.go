// Copyright (c) Encryption Consulting LLC
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

const waitForApproval = `  wait_for_approval = true
  timeouts {
    create = "10s"
    update = "10s"
  }
`

func TestCertificateResource_WaitForApprovalApproved(t *testing.T) {
	f := newFakeCertSecure(t)
	f.setMode(modeApproval)
	f.decideAfterPolls = 6
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories,
		Steps: []resource.TestStep{{
			// Approved while the apply waits: no error, no untaint.
			Config: certificateConfig(f.srv.URL, testCSR(t, "approved.example.com"), waitForApproval),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr(testAddr, "enrollment_id", "1501"),
				resource.TestCheckResourceAttr(testAddr, "status", "active"),
				resource.TestCheckResourceAttr(testAddr, "wait_for_approval", "true"),
				resource.TestMatchResourceAttr(testAddr, "certificate_pem", regexp.MustCompile(`^-----BEGIN CERTIFICATE-----`)),
				checkCount("enroll_csr", f.enrollCount, 1),
			),
		}},
	})
}

func TestCertificateResource_WaitForApprovalDenied(t *testing.T) {
	f := newFakeCertSecure(t)
	f.setMode(modeApproval)
	f.decideAfterPolls = 6
	f.denyApproval = true
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories,
		Steps: []resource.TestStep{{
			Config:      certificateConfig(f.srv.URL, testCSR(t, "denied.example.com"), waitForApproval),
			ExpectError: regexp.MustCompile(`(?s)Certificate request failed.*Denied By Approver.*enrollment ID \(eid\)\s+1501`),
		}},
	})
}

func TestCertificateResource_WaitForApprovalTimeout(t *testing.T) {
	f := newFakeCertSecure(t)
	f.setMode(modeApproval)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories,
		Steps: []resource.TestStep{{
			Config: certificateConfig(f.srv.URL, testCSR(t, "slow-approval.example.com"), `  wait_for_approval = true
  timeouts {
    create = "2s"
  }
`),
			ExpectError: regexp.MustCompile(`(?s)Timed out waiting for approval.*enrollment ID \(eid\)\s+1501,\s+task\s+ID\s+20001.*Approve\s+or\s+deny.*terraform\s+untaint`),
		}},
	})
	if n := f.enrollCount(); n != 1 {
		t.Fatalf("enroll_csr called %d times, want 1", n)
	}
}

func TestCertificateRenewal_WaitForApproval(t *testing.T) {
	f := newFakeCertSecure(t)
	key2 := testKey(t)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories,
		Steps: []resource.TestStep{
			{Config: certificateConfig(f.srv.URL, testCSR(t, "app.example.com"), waitForApproval)},
			{
				// The renewal awaits approval and is approved while the apply waits.
				PreConfig: func() {
					f.setMode(modeApproval)
					f.decideAfterPolls = 6
				},
				Config: certificateConfig(f.srv.URL, testCSRForKey(t, key2, "app.example.com"), waitForApproval),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testAddr, "enrollment_id", "1502"),
					resource.TestCheckNoResourceAttr(testAddr, "pending_renewal_task_id"),
					checkCertKey(key2.Public()),
					checkCount("renew_csr", f.renewCount, 1),
				),
			},
		},
	})
}
