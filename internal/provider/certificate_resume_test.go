// Copyright (c) Encryption Consulting LLC
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
)

// untaint does what terraform untaint does to every resource in the state
// files under dir, the TestCase working directory.
func untaint(t *testing.T, dir string) {
	t.Helper()
	found := false
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != "terraform.tfstate" {
			return err
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var st map[string]any
		if err := json.Unmarshal(raw, &st); err != nil {
			return err
		}
		resources, _ := st["resources"].([]any)
		for _, r := range resources {
			res, _ := r.(map[string]any)
			instances, _ := res["instances"].([]any)
			for _, inst := range instances {
				if m, ok := inst.(map[string]any); ok && m["status"] == "tainted" {
					delete(m, "status")
					found = true
				}
			}
		}
		out, err := json.MarshalIndent(st, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(p, out, 0o600)
	})
	if err != nil {
		t.Fatalf("untainting state: %v", err)
	}
	if !found {
		t.Fatalf("no tainted resource in the state under %s", dir)
	}
}

func expectReplace() resource.ConfigPlanChecks {
	return resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(testAddr, plancheck.ResourceActionDestroyBeforeCreate)}}
}

var createPendingErr = regexp.MustCompile(`(?s)requires approval.*enrollment ID \(eid\)\s+1501,\s+task\s+ID\s+20001.*terraform\s+untaint`)

func TestCertificateResource_PendingApprovalResumesAfterUntaint(t *testing.T) {
	f := newFakeCertSecure(t)
	f.setMode(modeApproval)
	dir := t.TempDir()
	key := testKey(t)
	cfg := certificateConfig(f.srv.URL, testCSRForKey(t, key, "pending.example.com"), "")

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories,
		WorkingDir:               dir,
		Steps: []resource.TestStep{
			{Config: cfg, ExpectError: createPendingErr},
			{
				// Untainted and still waiting: the apply resumes and does not submit again.
				PreConfig:        func() { untaint(t, dir) },
				Config:           cfg,
				ConfigPlanChecks: expectUpdate(),
				ExpectError:      regexp.MustCompile(`(?s)requires approval.*task\s+ID\s+20001.*resumes\s+this\s+request`),
			},
			{
				// Approved in CertSecure: the next apply downloads the same request.
				PreConfig:        func() { f.setTaskMode("20001", modeIssue) },
				Config:           cfg,
				ConfigPlanChecks: expectUpdate(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testAddr, "id", "1501"),
					resource.TestCheckResourceAttr(testAddr, "enrollment_id", "1501"),
					resource.TestCheckResourceAttr(testAddr, "task_id", "20001"),
					resource.TestCheckResourceAttr(testAddr, "status", "active"),
					checkCertKey(key.Public()),
					checkCount("enroll_csr", f.enrollCount, 1),
				),
			},
			{Config: cfg, PlanOnly: true},
		},
	})
}

func TestCertificateResource_TimeoutResumesAfterUntaint(t *testing.T) {
	f := newFakeCertSecure(t)
	f.setMode(modeStuck)
	dir := t.TempDir()
	cfg := certificateConfig(f.srv.URL, testCSR(t, "slow.example.com"), `
  timeouts {
    create = "2s"
  }
`)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories,
		WorkingDir:               dir,
		Steps: []resource.TestStep{
			{Config: cfg, ExpectError: regexp.MustCompile(`(?s)Timed out waiting.*1501.*terraform\s+untaint`)},
			{
				PreConfig: func() {
					untaint(t, dir)
					f.setTaskMode("20001", modeIssue)
				},
				Config: cfg,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testAddr, "enrollment_id", "1501"),
					resource.TestCheckResourceAttr(testAddr, "status", "active"),
					checkCount("enroll_csr", f.enrollCount, 1),
				),
			},
		},
	})
}

func TestCertificateResource_PendingDeniedIsReplaced(t *testing.T) {
	f := newFakeCertSecure(t)
	f.setMode(modeApproval)
	dir := t.TempDir()
	cfg := certificateConfig(f.srv.URL, testCSR(t, "denied.example.com"), "")

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories,
		WorkingDir:               dir,
		Steps: []resource.TestStep{
			{Config: cfg, ExpectError: createPendingErr},
			{
				// Denied by an approver: the next apply submits a new request.
				PreConfig: func() {
					untaint(t, dir)
					f.setTaskMode("20001", modeDenied)
					f.setStatus(1501, "denied")
					f.setMode(modeIssue)
				},
				Config:           cfg,
				ConfigPlanChecks: expectReplace(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testAddr, "enrollment_id", "1502"),
					resource.TestCheckResourceAttr(testAddr, "task_id", "20002"),
					checkCount("enroll_csr", f.enrollCount, 2),
				),
			},
		},
	})
}

func TestCertificateResource_PendingFailsWhileResumingIsReplaced(t *testing.T) {
	f := newFakeCertSecure(t)
	f.setMode(modeApproval)
	dir := t.TempDir()
	cfg := certificateConfig(f.srv.URL, testCSR(t, "wrong.example.com"), "")

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories,
		WorkingDir:               dir,
		Steps: []resource.TestStep{
			{Config: cfg, ExpectError: createPendingErr},
			{
				// The approved request returns a certificate for another key; the
				// record stays active, so private state marks it for replacement.
				PreConfig: func() {
					untaint(t, dir)
					f.setTaskMode("20001", modeWrongKey)
				},
				Config:      cfg,
				ExpectError: regexp.MustCompile(`(?s)does not match the CSR.*replaces\s+the\s+resource`),
			},
			{
				PreConfig:        func() { f.setMode(modeIssue) },
				Config:           cfg,
				ConfigPlanChecks: expectReplace(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testAddr, "enrollment_id", "1502"),
					checkCount("enroll_csr", f.enrollCount, 2),
				),
			},
		},
	})
}

func TestCertificateResource_PendingCSRChangeIsReplaced(t *testing.T) {
	f := newFakeCertSecure(t)
	f.setMode(modeApproval)
	dir := t.TempDir()
	key2 := testKey(t)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories,
		WorkingDir:               dir,
		Steps: []resource.TestStep{
			{Config: certificateConfig(f.srv.URL, testCSR(t, "app.example.com"), ""), ExpectError: createPendingErr},
			{
				PreConfig: func() {
					untaint(t, dir)
					f.setMode(modeIssue)
				},
				Config:           certificateConfig(f.srv.URL, testCSRForKey(t, key2, "app.example.com"), ""),
				ConfigPlanChecks: expectReplace(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testAddr, "enrollment_id", "1502"),
					checkCertKey(key2.Public()),
					checkCount("enroll_csr", f.enrollCount, 2),
				),
			},
		},
	})
}

func TestCertificateResource_PendingTaintedSubmitsNew(t *testing.T) {
	f := newFakeCertSecure(t)
	f.setMode(modeApproval)
	cfg := certificateConfig(f.srv.URL, testCSR(t, "pending.example.com"), "")

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories,
		Steps: []resource.TestStep{
			{Config: cfg, ExpectError: createPendingErr},
			{
				// Without untaint, Terraform replaces the tainted request as before.
				PreConfig:        func() { f.setMode(modeIssue) },
				Config:           cfg,
				ConfigPlanChecks: expectReplace(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testAddr, "enrollment_id", "1502"),
					checkCount("enroll_csr", f.enrollCount, 2),
				),
			},
		},
	})
}
