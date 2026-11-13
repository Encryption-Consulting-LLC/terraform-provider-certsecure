---
page_title: "Delivering Certificates to Azure Key Vault"
subcategory: ""
description: |-
  Issue a certificate from Microsoft CA through CertSecure and import it into Azure Key Vault as a PEM certificate.
---

# Delivering Certificates to Azure Key Vault

This guide issues a certificate from Microsoft CA through CertSecure and imports it into Azure Key Vault with the
Azure provider's `azurerm_key_vault_certificate`.

```
tls_private_key → tls_cert_request → certsecure_certificate → azurerm_key_vault_certificate
```

The CertSecure provider never talks to Azure. It issues and renews the certificate; the Azure provider imports it.

## Example

```terraform
# Issue a certificate from Microsoft CA through CertSecure and import it into
# Azure Key Vault as a PEM certificate. Renewals import a new version of the
# same Key Vault certificate, so versionless IDs do not change.
#
# The private key is stored in Terraform state: see the state security guide.

terraform {
  required_providers {
    certsecure = {
      source  = "encryption-consulting-llc/certsecure"
      version = "~> 1.2"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}

provider "certsecure" {}

provider "azurerm" {
  features {}
}

variable "key_vault_id" {
  type = string
}

# 1. Key and CSR, created by Terraform. CertSecure only receives the CSR.
resource "tls_private_key" "app" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_cert_request" "app" {
  private_key_pem = tls_private_key.app.private_key_pem

  subject {
    common_name = "app.example.com"
  }
  dns_names = ["app.example.com"]
}

# 2. Certificate from Microsoft CA through CertSecure.
resource "certsecure_certificate" "app" {
  csr_pem  = tls_cert_request.app.cert_request_pem
  ca_name  = "Issuing-CA-01"
  template = "WebServer"

  # Renew in place when the certificate expires within 30 days.
  early_renewal_hours = 720

  # Revoke on destroy, but only after a replacement is in use.
  revoke_on_destroy = true
  lifecycle {
    create_before_destroy = true
  }
}

# 3. Import into Key Vault. The PEM contents hold the key (PKCS#8), the
#    certificate and its chain. A renewal or a new key imports a new version.
resource "azurerm_key_vault_certificate" "app" {
  name         = "app-example-com"
  key_vault_id = var.key_vault_id

  certificate {
    contents = join("", [
      tls_private_key.app.private_key_pem_pkcs8,
      certsecure_certificate.app.certificate_pem,
      certsecure_certificate.app.chain_pem,
    ])
  }

  certificate_policy {
    issuer_parameters {
      name = "Unknown"
    }
    key_properties {
      exportable = true
      key_type   = "RSA"
      key_size   = 2048
      reuse_key  = false
    }
    secret_properties {
      content_type = "application/x-pem-file"
    }
  }
}

# Services that support versionless references, such as Application Gateway
# or App Service, pick up each new version automatically.
output "versionless_secret_id" {
  value = azurerm_key_vault_certificate.app.versionless_secret_id
}
```

## The PEM contents

Key Vault imports a PEM certificate when the `certificate_policy` sets `content_type = "application/x-pem-file"`.
`contents` must hold the private key in PKCS#8 format followed by the certificate and its chain, which is why the
example uses `private_key_pem_pkcs8` and joins it with `certificate_pem` and `chain_pem`. Despite the attribute
description ("base64-encoded"), PEM text is passed as it is.

## Renewal creates a new version

When `certsecure_certificate` renews (the certificate expires within `early_renewal_hours`, or `csr_pem` changes), the
`contents` change in the same apply, and `azurerm_key_vault_certificate` imports them as a **new version of the same
Key Vault certificate**. The plan shows an in-place update.

`versionless_id` and `versionless_secret_id` do not change. Services that reference the certificate without a version,
such as Application Gateway or App Service, pick up the new version on their own. Services that reference a specific
version (`id`, `secret_id`) are updated by Terraform in the same apply when they are in the same configuration.

Renewal only happens when Terraform runs. Run `terraform apply` on a schedule, with an `early_renewal_hours` window
that covers missed runs.

## Rotating the key

To renew with a new key, replace the key: for example `terraform apply -replace=tls_private_key.app`, or a
`replace_triggered_by` on a version value. The new key gives a new CSR, `certsecure_certificate` renews with it, and
Key Vault imports the new key and certificate as a new version.

## Replacement and revocation

Changing `ca_name`, `template` or another argument that cannot be renewed issues a new certificate. With
`create_before_destroy`, the new certificate is issued and imported before the old one is revoked
(`revoke_on_destroy = true`).

## Things to know

- **Permissions.** The identity running Terraform needs to import and read certificates in the vault, for example the
  *Key Vault Certificates Officer* role with Azure RBAC, or the `Import`, `Get`, `List` and `Delete` certificate
  permissions with access policies.
- **Destroy.** Destroying `azurerm_key_vault_certificate` soft-deletes it when soft delete is enabled on the vault. A
  certificate with the same name cannot be created again until it is purged or recovered; see the Azure provider's
  `key_vault` features block.
- **State.** The private key is stored in state by `tls_private_key`, `tls_cert_request` and
  `azurerm_key_vault_certificate` (in `certificate.contents`). See the
  [state security guide](https://registry.terraform.io/providers/encryption-consulting-llc/certsecure/latest/docs/guides/state-security).
