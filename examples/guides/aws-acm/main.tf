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
