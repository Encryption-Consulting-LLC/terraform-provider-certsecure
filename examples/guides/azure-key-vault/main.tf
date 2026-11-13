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
