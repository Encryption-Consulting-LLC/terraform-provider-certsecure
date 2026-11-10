data "certsecure_templates" "issuing" {
  ca_name = "Issuing-CA-01"
}

# Template names to use as certsecure_certificate.template.
output "template_names" {
  value = data.certsecure_templates.issuing.names
}

# Template details, keyed by display name.
output "template_validity" {
  value = { for t in data.certsecure_templates.issuing.templates : t.friendly_name => t.validity_period }
}
