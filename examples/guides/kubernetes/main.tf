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
