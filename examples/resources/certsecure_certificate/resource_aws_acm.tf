# Deliver the certificate with the destination's own provider, here AWS
# Certificate Manager. Renewals re-import into the same ACM certificate (ARN).
# The private key is stored in Terraform state by tls_private_key,
# tls_cert_request and aws_acm_certificate: see the state security guide.
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

resource "certsecure_certificate" "web" {
  csr_pem             = tls_cert_request.web.cert_request_pem
  ca_name             = "Issuing-CA-01"
  template            = "WebServer"
  early_renewal_hours = 720
}

resource "aws_acm_certificate" "web" {
  private_key       = tls_private_key.web.private_key_pem
  certificate_body  = certsecure_certificate.web.certificate_pem
  certificate_chain = certsecure_certificate.web.chain_pem
}
