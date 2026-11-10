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
// Only TestAccCertificateRevoke revokes its certificate; revoke the others in
// CertSecure if needed.

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

  subject_alternative_names {
    dns = [%q]
  }
}
`, strings.TrimSpace(testAccCSR(t, cn)), os.Getenv("CERTSECURE_TEST_CA"), os.Getenv("CERTSECURE_TEST_TEMPLATE"), "alt-"+cn)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					func(s *terraform.State) error {
						rs := s.RootModule().Resources["certsecure_certificate.test"].Primary
						t.Logf("issued certificate: enrollment_id=%s task_id=%s serial=%s (not revoked by this test)",
							rs.Attributes["enrollment_id"], rs.Attributes["task_id"], rs.Attributes["serial_number"])
						return nil
					},
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
				ResourceName:            "certsecure_certificate.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"csr_pem", "owner_email", "tags", "notes", "subject_alternative_names", "task_id", "timeouts"},
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
}
`, strings.TrimSpace(csr), os.Getenv("CERTSECURE_TEST_CA"), os.Getenv("CERTSECURE_TEST_TEMPLATE"))
	}
	var eids []string
	record := func(want *rsa.PrivateKey) resource.TestCheckFunc {
		return func(s *terraform.State) error {
			rs := s.RootModule().Resources["certsecure_certificate.test"].Primary
			t.Logf("certificate: enrollment_id=%s task_id=%s serial=%s (not revoked by this test)",
				rs.Attributes["enrollment_id"], rs.Attributes["task_id"], rs.Attributes["serial_number"])
			if slices.Contains(eids, rs.Attributes["enrollment_id"]) {
				return fmt.Errorf("enrollment_id %s did not change", rs.Attributes["enrollment_id"])
			}
			eids = append(eids, rs.Attributes["enrollment_id"])
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

	var eid int64
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testProviderFactories,
		Steps: []resource.TestStep{{
			Config: config,
			Check: func(s *terraform.State) error {
				rs := s.RootModule().Resources["certsecure_certificate.test"].Primary
				t.Logf("issued certificate: enrollment_id=%s task_id=%s serial=%s (revoked on destroy)",
					rs.Attributes["enrollment_id"], rs.Attributes["task_id"], rs.Attributes["serial_number"])
				var err error
				eid, err = strconv.ParseInt(rs.Attributes["enrollment_id"], 10, 64)
				return err
			},
		}},
		CheckDestroy: func(*terraform.State) error {
			c, err := client.New(client.Config{URL: os.Getenv(envURL), Token: os.Getenv(envToken)})
			if err != nil {
				return err
			}
			d, err := c.GetEnrollmentDetails(context.Background(), eid)
			if err != nil {
				return err
			}
			if !strings.EqualFold(d.Status, "revoked") {
				return fmt.Errorf("enrollment %d status = %q after destroy, want revoked", eid, d.Status)
			}
			t.Logf("enrollment_id=%d revoked", eid)
			return nil
		},
	})
}
