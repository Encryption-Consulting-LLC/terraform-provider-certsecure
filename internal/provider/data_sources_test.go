// Copyright (c) Encryption Consulting LLC
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"fmt"
	"regexp"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCAsDataSource(t *testing.T) {
	f := newFakeCertSecure(t)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories,
		Steps: []resource.TestStep{{
			Config: providerBlock(f.srv.URL) + `
data "certsecure_cas" "all" {}

data "certsecure_cas" "msca" {
  type = "msca"
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr("data.certsecure_cas.msca", "names.#", "3"),
				resource.TestCheckResourceAttr("data.certsecure_cas.msca", "names.2", "Example Issuing CA"),
				resource.TestCheckResourceAttr("data.certsecure_cas.msca", "cas.#", "3"),
				resource.TestCheckResourceAttr("data.certsecure_cas.msca", "cas.2.name", "Example Issuing CA"),
				resource.TestCheckResourceAttr("data.certsecure_cas.msca", "cas.2.type", "MSCA"),
				resource.TestCheckResourceAttr("data.certsecure_cas.msca", "cas.2.connectors.#", "1"),
				resource.TestCheckResourceAttrWith("data.certsecure_cas.all", "cas.#", func(v string) error {
					if n, _ := strconv.Atoi(v); n <= 3 {
						return fmt.Errorf("expected all CA types, got %s CAs", v)
					}
					return nil
				}),
			),
		}},
	})
}

func TestTemplatesDataSource(t *testing.T) {
	f := newFakeCertSecure(t)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories,
		Steps: []resource.TestStep{{
			Config: providerBlock(f.srv.URL) + `
data "certsecure_templates" "rca" {
  ca_name = "Example Issuing CA"
}

data "certsecure_templates" "empty" {
  ca_name = "Offline CA"
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr("data.certsecure_templates.rca", "names.#", "11"),
				resource.TestCheckTypeSetElemAttr("data.certsecure_templates.rca", "names.*", "WebServer"),
				resource.TestCheckResourceAttr("data.certsecure_templates.rca", "templates.#", "11"),
				resource.TestCheckTypeSetElemNestedAttrs("data.certsecure_templates.rca", "templates.*", map[string]string{
					"friendly_name":   "Web Server",
					"validity_period": "2 Years",
					"min_key_size":    "2048",
				}),
				resource.TestCheckResourceAttr("data.certsecure_templates.empty", "names.#", "0"),
				resource.TestCheckResourceAttr("data.certsecure_templates.empty", "templates.#", "0"),
			),
		}},
	})
}

func TestProviderConfigure_Errors(t *testing.T) {
	f := newFakeCertSecure(t)
	cases := map[string]struct {
		config string
		err    string
	}{
		"bad token": {fmt.Sprintf(`
provider "certsecure" {
  url   = %q
  token = "wrong"
}
`, f.srv.URL), `CertSecure token missing, invalid, or expired`},
		"bad timeout": {fmt.Sprintf(`
provider "certsecure" {
  url             = %q
  token           = %q
  request_timeout = "fast"
}
`, f.srv.URL, fakeToken), `Invalid duration`},
		"bad url": {`
provider "certsecure" {
  url   = "ftp://certsecure.example.com"
  token = "x"
}
`, `scheme must be https`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			resource.UnitTest(t, resource.TestCase{
				ProtoV6ProviderFactories: testProviderFactories,
				Steps: []resource.TestStep{{
					Config:      tc.config + "\ndata \"certsecure_cas\" \"all\" {}\n",
					ExpectError: regexp.MustCompile(tc.err),
				}},
			})
		})
	}
}

func TestProviderConfigure_EnvFallback(t *testing.T) {
	f := newFakeCertSecure(t)
	t.Setenv(envURL, f.srv.URL)
	t.Setenv(envToken, fakeToken)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories,
		Steps: []resource.TestStep{{
			Config: `
provider "certsecure" {}

data "certsecure_cas" "all" {}
`,
			Check: resource.TestCheckResourceAttrSet("data.certsecure_cas.all", "names.0"),
		}},
	})
}

func TestProviderConfigure_MissingURL(t *testing.T) {
	t.Setenv(envURL, "")
	t.Setenv(envToken, "")
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories,
		Steps: []resource.TestStep{{
			Config: `
provider "certsecure" {}

data "certsecure_cas" "all" {}
`,
			ExpectError: regexp.MustCompile(`Missing CertSecure URL`),
		}},
	})
}
