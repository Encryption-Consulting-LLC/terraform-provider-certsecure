# All CAs the token may enroll from.
data "certsecure_cas" "all" {}

# Only Microsoft CAs.
data "certsecure_cas" "msca" {
  type = "MSCA"
}

output "msca_names" {
  value = data.certsecure_cas.msca.names
}
