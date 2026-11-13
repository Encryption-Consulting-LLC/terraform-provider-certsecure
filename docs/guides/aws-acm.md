---
page_title: "Delivering Certificates to AWS Certificate Manager"
subcategory: ""
description: |-
  Issue a certificate from Microsoft CA through CertSecure, import it into AWS Certificate Manager and serve it on an Application Load Balancer.
---

# Delivering Certificates to AWS Certificate Manager

This guide issues a certificate from Microsoft CA through CertSecure, imports it into AWS Certificate Manager (ACM)
with the AWS provider's `aws_acm_certificate`, and serves it on an Application Load Balancer HTTPS listener.

```
tls_private_key → tls_cert_request → certsecure_certificate → aws_acm_certificate → aws_lb_listener
```

The CertSecure provider never talks to AWS. It issues and renews the certificate; the AWS provider imports it.

## Example

```terraform
# Issue a certificate from Microsoft CA through CertSecure, import it into AWS
# Certificate Manager and serve it on an Application Load Balancer listener.
# Renewals re-import into the same ACM certificate, so the ARN and the listener
# do not change.
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
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "certsecure" {}

provider "aws" {
  region = "us-east-1"
}

variable "load_balancer_arn" {
  type = string
}

variable "target_group_arn" {
  type = string
}

# 1. Key and CSR, created by Terraform. CertSecure only receives the CSR.
resource "tls_private_key" "web" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_cert_request" "web" {
  private_key_pem = tls_private_key.web.private_key_pem

  subject {
    common_name = "web.example.com"
  }
  dns_names = ["web.example.com"]
}

# 2. Certificate from Microsoft CA through CertSecure.
resource "certsecure_certificate" "web" {
  csr_pem  = tls_cert_request.web.cert_request_pem
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

# 3. Import into ACM. A renewal or a new key re-imports into the same ARN.
resource "aws_acm_certificate" "web" {
  private_key       = tls_private_key.web.private_key_pem
  certificate_body  = certsecure_certificate.web.certificate_pem
  certificate_chain = certsecure_certificate.web.chain_pem

  tags = {
    Name = "web.example.com"
  }
}

# 4. Serve it on an HTTPS listener.
resource "aws_lb_listener" "https" {
  load_balancer_arn = var.load_balancer_arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate.web.arn

  default_action {
    type             = "forward"
    target_group_arn = var.target_group_arn
  }
}

output "acm_certificate_arn" {
  value = aws_acm_certificate.web.arn
}
```

## Renewal keeps the same ARN

When `certsecure_certificate` renews (the certificate expires within `early_renewal_hours`, or `csr_pem` changes),
`certificate_pem` and `chain_pem` change in the same apply. `aws_acm_certificate` then re-imports the renewed
certificate into the **same ACM certificate**: the ARN does not change, so the listener and every other service that
uses the ARN keep working without a change. The plan shows an in-place update of `aws_acm_certificate`, not a
replacement.

Renewal only happens when Terraform runs. Run `terraform apply` on a schedule, with an `early_renewal_hours` window
that covers missed runs.

## Rotating the key

To renew with a new key, replace the key: for example `terraform apply -replace=tls_private_key.web`, or a
`replace_triggered_by` on a version value. The new key gives a new CSR, `certsecure_certificate` renews with it, and
`aws_acm_certificate` re-imports the new certificate and key into the same ARN in the same apply.

## Replacement and revocation

Changing `ca_name`, `template` or another argument that cannot be renewed issues a new certificate. With
`create_before_destroy`, the new certificate is issued and imported into ACM before the old one is revoked
(`revoke_on_destroy = true`). Without `create_before_destroy`, the old certificate would be revoked while the load
balancer still serves it.

## Things to know

- **`not_after` of the ACM resource lags one run.** Right after a renewal, `aws_acm_certificate.web.not_after` (and
  outputs that use it) can still show the previous expiry date; the next `terraform apply` or `terraform refresh`
  shows the new one. The certificate in ACM is already the renewed one. For the current expiry date, use
  `certsecure_certificate.web.not_after`.
- **Region.** An imported certificate is available only in the region it was imported into. Import it in the load
  balancer's region; for CloudFront, import it in `us-east-1`.
- **Chain.** `chain_pem` holds the issuing CA chain without the leaf, which is what `certificate_chain` expects.
- **Destroy.** Destroying the configuration deletes the ACM certificate. ACM refuses to delete a certificate that is
  still in use, so Terraform removes the listener first when both are in the same configuration.
- **State.** The private key is stored in state by `tls_private_key`, `tls_cert_request` and `aws_acm_certificate`.
  With AWS provider 6.47.0 and later, `private_key_wo` keeps it out of the ACM resource's state. See the
  [state security guide](https://registry.terraform.io/providers/encryption-consulting-llc/certsecure/latest/docs/guides/state-security).
