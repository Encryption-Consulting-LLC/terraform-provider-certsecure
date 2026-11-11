# Read a certificate that already exists in CertSecure, for example one
# requested in the CertSecure portal, by its enrollment ID (eid).
data "certsecure_certificate" "web" {
  enrollment_id = 1501
}

output "web_certificate_expires" {
  value = data.certsecure_certificate.web.not_after
}

output "web_certificate_status" {
  value = data.certsecure_certificate.web.status
}
