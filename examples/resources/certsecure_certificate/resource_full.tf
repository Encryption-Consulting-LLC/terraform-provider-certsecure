# Full CSR enrollment with renewal, revocation, SANs and metadata.
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

resource "certsecure_certificate" "app" {
  csr_pem     = tls_cert_request.app.cert_request_pem
  ca_name     = "Issuing-CA-01"
  template    = "WebServer"
  owner_email = "app-team@example.com"
  tags        = ["terraform", "app"]
  notes       = "Managed by Terraform"

  # Renew in place, with the same CSR, when the certificate expires within 30 days.
  early_renewal_hours = 720

  # Revoke the certificate in CertSecure when the resource is destroyed or replaced.
  revoke_on_destroy = true

  # Optional: request additional SANs.
  subject_alternative_names {
    dns = ["www.example.com"]
    ip  = ["192.0.2.10"]
  }

  timeouts {
    create = "10m"
    update = "10m"
    delete = "10m"
  }

  # Issue a replacement before revoking the old certificate.
  lifecycle {
    create_before_destroy = true
  }
}

output "certificate_pem" {
  value = certsecure_certificate.app.certificate_pem
}

output "chain_pem" {
  value = certsecure_certificate.app.chain_pem
}

output "serial_number" {
  value = certsecure_certificate.app.serial_number
}
