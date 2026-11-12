// Copyright (c) Encryption Consulting LLC
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/Encryption-Consulting-LLC/terraform-provider-certsecure/internal/client"
)

// Acceptance tests run against a real CertSecure deployment and ISSUE REAL
// CERTIFICATES (one per run of TestAccCertificate and TestAccCertificateRevoke,
// three per run of TestAccCertificateRenewal). They require TF_ACC=1 and:
//
//	CERTSECURE_URL, CERTSECURE_TOKEN   provider credentials
//	CERTSECURE_TEST_CA                 CA name, e.g. "Issuing CA"
//	CERTSECURE_TEST_TEMPLATE           template that issues without approval
//
// Every certificate is revoked again when the test ends: the current one by
// revoke_on_destroy, the ones TestAccCertificateRenewal renewed by the test
// itself. CheckDestroy verifies that all of them are revoked.

// testAccClient returns an API client for the acceptance test deployment.
func testAccClient() (*client.Client, error) {
	return client.New(client.Config{URL: os.Getenv(envURL), Token: os.Getenv(envToken)})
}

// testAccEID records the enrollment ID of certsecure_certificate.test in *eids.
func testAccEID(t *testing.T, eids *[]int64) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs := s.RootModule().Resources["certsecure_certificate.test"].Primary
		t.Logf("certificate: enrollment_id=%s task_id=%s serial=%s",
			rs.Attributes["enrollment_id"], rs.Attributes["task_id"], rs.Attributes["serial_number"])
		eid, err := strconv.ParseInt(rs.Attributes["enrollment_id"], 10, 64)
		if err != nil {
			return err
		}
		if slices.Contains(*eids, eid) {
			return fmt.Errorf("enrollment_id %d did not change", eid)
		}
		*eids = append(*eids, eid)
		return nil
	}
}

// testAccCheckRevoked returns a CheckDestroy that revokes all but the last of
// *eids when revokeRenewed is set (destroy revokes only the current
// certificate), then checks that all of them are revoked.
func testAccCheckRevoked(t *testing.T, eids *[]int64, revokeRenewed bool) func(*terraform.State) error {
	return func(*terraform.State) error {
		c, err := testAccClient()
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		for i, eid := range *eids {
			if revokeRenewed && i < len(*eids)-1 {
				taskID, err := c.RevokeCert(ctx, eid)
				if err != nil {
					return fmt.Errorf("revoking renewed certificate %d: %w", eid, err)
				}
				t.Logf("revoking renewed certificate: enrollment_id=%d task_id=%s", eid, taskID)
			}
			if err := testAccWaitRevoked(ctx, c, eid); err != nil {
				return err
			}
			t.Logf("enrollment_id=%d revoked", eid)
		}
		return nil
	}
}

// testAccWaitRevoked waits until CertSecure reports eid as revoked.
func testAccWaitRevoked(ctx context.Context, c *client.Client, eid int64) error {
	for {
		d, err := c.GetEnrollmentDetails(ctx, eid)
		if err == nil && strings.EqualFold(d.Status, "revoked") {
			return nil
		}
		select {
		case <-ctx.Done():
			if err != nil {
				return fmt.Errorf("enrollment %d not revoked after destroy: %w", eid, err)
			}
			return fmt.Errorf("enrollment %d status = %q after destroy, want revoked", eid, d.Status)
		case <-time.After(3 * time.Second):
		}
	}
}

func testAccPreCheck(t *testing.T) {
	t.Helper()
	for _, v := range []string{envURL, envToken, "CERTSECURE_TEST_CA", "CERTSECURE_TEST_TEMPLATE"} {
		if os.Getenv(v) == "" {
			t.Fatalf("%s must be set for acceptance tests", v)
		}
	}
}

// testAccCSR returns an RSA 2048 CSR; Microsoft CA templates commonly require RSA.
func testAccCSR(t *testing.T, cn string) string {
	t.Helper()
	return testAccCSRForKey(t, testAccKey(t), cn, cn)
}

func testAccKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func testAccCSRForKey(t *testing.T, key *rsa.PrivateKey, cn string, dns ...string) string {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}, DNSNames: dns}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func TestAccDataSources(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testProviderFactories,
		Steps: []resource.TestStep{{
			Config: fmt.Sprintf(`
data "certsecure_cas" "all" {}

data "certsecure_templates" "test" {
  ca_name = %q
}
`, os.Getenv("CERTSECURE_TEST_CA")),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckTypeSetElemAttr("data.certsecure_cas.all", "names.*", os.Getenv("CERTSECURE_TEST_CA")),
				resource.TestCheckTypeSetElemAttr("data.certsecure_templates.test", "names.*", os.Getenv("CERTSECURE_TEST_TEMPLATE")),
			),
		}},
	})
}

func TestAccCertificate(t *testing.T) {
	cn := fmt.Sprintf("tf-acc-%d.example.com", time.Now().Unix())
	config := fmt.Sprintf(`
resource "certsecure_certificate" "test" {
  csr_pem  = <<-EOT
%s
  EOT
  ca_name  = %q
  template = %q
  tags     = ["terraform-acceptance-test"]
  notes    = "terraform-provider-certsecure acceptance test"

  revoke_on_destroy = true

  subject_alternative_names {
    dns = [%q]
  }
}
`, strings.TrimSpace(testAccCSR(t, cn)), os.Getenv("CERTSECURE_TEST_CA"), os.Getenv("CERTSECURE_TEST_TEMPLATE"), "alt-"+cn)

	var eids []int64
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testProviderFactories,
		CheckDestroy:             testAccCheckRevoked(t, &eids, false),
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccEID(t, &eids),
					resource.TestCheckResourceAttr("certsecure_certificate.test", "status", "active"),
					resource.TestMatchResourceAttr("certsecure_certificate.test", "enrollment_id", regexp.MustCompile(`^\d+$`)),
					resource.TestMatchResourceAttr("certsecure_certificate.test", "serial_number", regexp.MustCompile(`^[0-9a-f]+$`)),
					resource.TestMatchResourceAttr("certsecure_certificate.test", "certificate_pem", regexp.MustCompile(`^-----BEGIN CERTIFICATE-----`)),
					resource.TestMatchResourceAttr("certsecure_certificate.test", "chain_pem", regexp.MustCompile(`^-----BEGIN CERTIFICATE-----`)),
					resource.TestMatchResourceAttr("certsecure_certificate.test", "not_after", regexp.MustCompile(`^\d{4}-\d\d-\d\dT`)),
				),
			},
			{
				Config:   config,
				PlanOnly: true,
			},
			{
				// The data source reads the same certificate; nothing new is issued.
				Config: config + `
data "certsecure_certificate" "test" {
  enrollment_id = certsecure_certificate.test.enrollment_id
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.certsecure_certificate.test", "status", "active"),
					resource.TestCheckResourceAttrPair("data.certsecure_certificate.test", "certificate_pem", "certsecure_certificate.test", "certificate_pem"),
					resource.TestCheckResourceAttrPair("data.certsecure_certificate.test", "chain_pem", "certsecure_certificate.test", "chain_pem"),
					resource.TestCheckResourceAttrPair("data.certsecure_certificate.test", "serial_number", "certsecure_certificate.test", "serial_number"),
					resource.TestCheckResourceAttrPair("data.certsecure_certificate.test", "ca_name", "certsecure_certificate.test", "ca_name"),
					resource.TestCheckResourceAttrPair("data.certsecure_certificate.test", "template", "certsecure_certificate.test", "template"),
				),
			},
			{
				// Lookup by serial number (upper case) and CA finds the same enrollment.
				Config: config + `
data "certsecure_certificate" "test" {
  serial_number = upper(certsecure_certificate.test.serial_number)
  ca_name       = certsecure_certificate.test.ca_name
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair("data.certsecure_certificate.test", "enrollment_id", "certsecure_certificate.test", "enrollment_id"),
					resource.TestCheckResourceAttrPair("data.certsecure_certificate.test", "certificate_pem", "certsecure_certificate.test", "certificate_pem"),
					resource.TestCheckResourceAttrPair("data.certsecure_certificate.test", "template", "certsecure_certificate.test", "template"),
				),
			},
			{
				ResourceName:            "certsecure_certificate.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"csr_pem", "owner_email", "tags", "notes", "subject_alternative_names", "task_id", "timeouts", "revoke_on_destroy"},
			},
		},
	})
}

// TestAccCertificateRenewal issues a certificate, then renews it in place
// twice through renew_csr: with a new CSR for the same key (another SAN), then
// with a CSR for a new key. The backend must support renew_csr.
func TestAccCertificateRenewal(t *testing.T) {
	cn := fmt.Sprintf("tf-acc-renew-%d.example.com", time.Now().Unix())
	key := testAccKey(t)
	config := func(csr string) string {
		return fmt.Sprintf(`
resource "certsecure_certificate" "test" {
  csr_pem  = <<-EOT
%s
  EOT
  ca_name  = %q
  template = %q
  tags     = ["terraform-acceptance-test"]
  notes    = "terraform-provider-certsecure renewal acceptance test"

  revoke_on_destroy = true
}
`, strings.TrimSpace(csr), os.Getenv("CERTSECURE_TEST_CA"), os.Getenv("CERTSECURE_TEST_TEMPLATE"))
	}
	var eids []int64
	record := func(want *rsa.PrivateKey) resource.TestCheckFunc {
		return func(s *terraform.State) error {
			if err := testAccEID(t, &eids)(s); err != nil {
				return err
			}
			rs := s.RootModule().Resources["certsecure_certificate.test"].Primary
			cert, err := parseCertificatePEM(rs.Attributes["certificate_pem"])
			if err != nil {
				return err
			}
			if !publicKeysEqual(cert.PublicKey, want.Public()) {
				return fmt.Errorf("certificate is not for the configured key")
			}
			return nil
		}
	}
	inPlace := resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
		plancheck.ExpectResourceAction("certsecure_certificate.test", plancheck.ResourceActionUpdate),
	}}
	newKey := testAccKey(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testProviderFactories,
		// Renewal keeps the previous certificates valid, so the test revokes them.
		CheckDestroy: testAccCheckRevoked(t, &eids, true),
		Steps: []resource.TestStep{
			{
				Config: config(testAccCSRForKey(t, key, cn, cn)),
				Check:  record(key),
			},
			{
				// Same key, new CSR with another SAN.
				Config:           config(testAccCSRForKey(t, key, cn, cn, "alt-"+cn)),
				ConfigPlanChecks: inPlace,
				Check: resource.ComposeAggregateTestCheckFunc(
					record(key),
					resource.TestCheckResourceAttr("certsecure_certificate.test", "status", "active"),
					resource.TestCheckNoResourceAttr("certsecure_certificate.test", "pending_renewal_task_id"),
				),
			},
			{
				// New key.
				Config:           config(testAccCSRForKey(t, newKey, cn, cn)),
				ConfigPlanChecks: inPlace,
				Check:            record(newKey),
			},
		},
	})
}

// TestAccCertificateRevoke issues a certificate with revoke_on_destroy and
// checks that destroy revokes it in CertSecure.
func TestAccCertificateRevoke(t *testing.T) {
	cn := fmt.Sprintf("tf-acc-revoke-%d.example.com", time.Now().Unix())
	config := fmt.Sprintf(`
resource "certsecure_certificate" "test" {
  csr_pem           = <<-EOT
%s
  EOT
  ca_name           = %q
  template          = %q
  tags              = ["terraform-acceptance-test"]
  notes             = "terraform-provider-certsecure revocation acceptance test"
  revoke_on_destroy = true
}
`, strings.TrimSpace(testAccCSR(t, cn)), os.Getenv("CERTSECURE_TEST_CA"), os.Getenv("CERTSECURE_TEST_TEMPLATE"))

	var eids []int64
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testProviderFactories,
		Steps: []resource.TestStep{{
			Config: config,
			Check:  testAccEID(t, &eids),
		}},
		CheckDestroy: testAccCheckRevoked(t, &eids, false),
	})
}
