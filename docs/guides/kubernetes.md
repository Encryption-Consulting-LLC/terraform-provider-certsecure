---
page_title: "Delivering Certificates to Kubernetes"
subcategory: ""
description: |-
  Issue a certificate from Microsoft CA through CertSecure and store it in a Kubernetes TLS secret used by an Ingress.
---

# Delivering Certificates to Kubernetes

This guide issues a certificate from Microsoft CA through CertSecure and stores it in a Kubernetes TLS secret
(type `kubernetes.io/tls`) with the Kubernetes provider's `kubernetes_secret_v1`, for use by an Ingress.

```
tls_private_key → tls_cert_request → certsecure_certificate → kubernetes_secret_v1 → kubernetes_ingress_v1
```

The CertSecure provider never talks to the cluster. It issues and renews the certificate; the Kubernetes provider
writes the secret.

## Example

```terraform
# Issue a certificate from Microsoft CA through CertSecure and store it in a
# Kubernetes TLS secret (type kubernetes.io/tls) for an Ingress. Renewals update
# the same secret.
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
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.36"
    }
  }
}

provider "certsecure" {}

# Uses the current kubeconfig context.
provider "kubernetes" {
  config_path = "~/.kube/config"
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

# 3. TLS secret. tls.crt holds the certificate followed by its chain.
resource "kubernetes_secret_v1" "app_tls" {
  metadata {
    name      = "app-example-com-tls"
    namespace = "default"
  }

  type = "kubernetes.io/tls"

  data = {
    "tls.crt" = "${certsecure_certificate.app.certificate_pem}${certsecure_certificate.app.chain_pem}"
    "tls.key" = tls_private_key.app.private_key_pem
  }
}

# 4. Use the secret in an Ingress.
resource "kubernetes_ingress_v1" "app" {
  metadata {
    name      = "app"
    namespace = "default"
  }

  spec {
    tls {
      hosts       = ["app.example.com"]
      secret_name = kubernetes_secret_v1.app_tls.metadata[0].name
    }

    rule {
      host = "app.example.com"
      http {
        path {
          path      = "/"
          path_type = "Prefix"
          backend {
            service {
              name = "app"
              port {
                number = 80
              }
            }
          }
        }
      }
    }
  }
}
```

A `kubernetes.io/tls` secret needs the keys `tls.crt` and `tls.key`. `tls.crt` holds the certificate followed by its
chain (`certificate_pem` and `chain_pem`), so clients receive the intermediate CA certificates.

## Renewal updates the same secret

When `certsecure_certificate` renews (the certificate expires within `early_renewal_hours`, or `csr_pem` changes),
`tls.crt` changes in the same apply and Terraform updates the **same secret** in place. The Ingress keeps referencing
it by name. Most ingress controllers watch their TLS secrets and load the new certificate without a restart. Pods
that mount the secret as a volume see the new files after the kubelet syncs (not when mounted with `subPath`);
applications that read the certificate only at startup need a restart.

Renewal only happens when Terraform runs. Run `terraform apply` on a schedule, with an `early_renewal_hours` window
that covers missed runs.

## Rotating the key

To renew with a new key, replace the key: for example `terraform apply -replace=tls_private_key.app`, or a
`replace_triggered_by` on a version value. The new key gives a new CSR, `certsecure_certificate` renews with it, and
the secret is updated with the new certificate and key in the same apply.

## Replacement and revocation

Changing `ca_name`, `template` or another argument that cannot be renewed issues a new certificate. With
`create_before_destroy`, the new certificate is issued and written to the secret before the old one is revoked
(`revoke_on_destroy = true`).

## Keeping the key out of state

The private key is stored in state by `tls_private_key`, `tls_cert_request` and `kubernetes_secret_v1` (in `data`).
With Kubernetes provider 2.36.0 and later, the secret can take both keys from the write-only `data_wo` instead, with
the key from an ephemeral source:

```terraform
resource "kubernetes_secret_v1" "app_tls" {
  metadata {
    name      = "app-example-com-tls"
    namespace = "default"
  }

  type = "kubernetes.io/tls"

  data_wo = {
    "tls.crt" = "${certsecure_certificate.app.certificate_pem}${certsecure_certificate.app.chain_pem}"
    "tls.key" = var.private_key_pem # ephemeral variable
  }
  # data_wo is sent only when the revision changes: the enrollment ID changes
  # with every new or renewed certificate.
  data_wo_revision = certsecure_certificate.app.enrollment_id
}
```

Put both keys in `data_wo`: an update of `data` replaces the whole secret, so a key kept only in `data_wo` would be
removed. See the
[state security guide](https://registry.terraform.io/providers/encryption-consulting-llc/certsecure/latest/docs/guides/state-security)
for the ephemeral variable, the matching `tls_cert_request` configuration and the other options.
