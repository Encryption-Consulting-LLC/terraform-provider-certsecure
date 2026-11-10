terraform {
  required_providers {
    certsecure = {
      source = "encryption-consulting-llc/certsecure"
    }
  }
}

# The token is read from the CERTSECURE_TOKEN environment variable.
# The URL can also come from CERTSECURE_URL.
provider "certsecure" {
  url = "https://certsecure.example.com"
}
