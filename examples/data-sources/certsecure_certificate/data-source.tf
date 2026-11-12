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

# Or look it up by serial number and issuing CA, for example the serial number
# shown by a certificate viewer (upper or lower case, with or without colons).
data "certsecure_certificate" "api" {
  serial_number = "34:00:03:3B:A9:1E:D7:E5:49:45:75:30:E0:00:00:00:03:3B:A9"
  ca_name       = "Example Issuing CA"
}

output "api_certificate_enrollment_id" {
  value = data.certsecure_certificate.api.enrollment_id
}
