---
page_title: "Protecting the Private Key in Terraform State"
subcategory: ""
description: |-
  Where the private key ends up in Terraform state when certificates are issued with the CertSecure provider, and how to protect it or keep it out of state.
---

# Protecting the Private Key in Terraform State

The CertSecure provider never generates, receives or stores a private key. `certsecure_certificate` keeps only the
CSR, the issued certificate, its chain and CertSecure identifiers in state, and the API token is never written to
state.

The private key is created and delivered by other providers in the same configuration, and those providers usually
store it in state. **Anyone who can read the state can read the private key.** This guide shows where the key is
stored and how to protect it.

## Where the private key is stored

In the usual configuration (`tls_private_key` → `tls_cert_request` → `certsecure_certificate` → destination), the key
is stored in state by every resource that receives it:

| Resource                        | Attributes holding the private key                                         |
|---------------------------------|----------------------------------------------------------------------------|
| `tls_private_key`               | `private_key_pem`, `private_key_pem_pkcs8`, `private_key_openssh`          |
| `tls_cert_request`              | `private_key_pem`                                                          |
| `aws_acm_certificate`           | `private_key`                                                              |
| `azurerm_key_vault_certificate` | `certificate.contents` (PFX or PEM including the key), `certificate.password` |
| `kubernetes_secret_v1`          | `data` (for example `tls.key`)                                             |

Things to know:

- **`sensitive` is not encryption.** Sensitive attributes are hidden in plan output and the console, but are stored in
  plain text in the state file.
- **Saved plans contain the key too.** A plan file written with `terraform plan -out` holds the same values as the
  state. Protect plan files the same way, and delete them after use.
- **Outputs.** Never output the private key. `terraform output -raw` prints sensitive outputs in plain text.

## Protect the state

Use a remote backend that encrypts state at rest and restricts who can read it:

- **Amazon S3:** set `encrypt = true` and, preferably, a customer managed KMS key with `kms_key_id`. Restrict the
  bucket and the KMS key to the identities that run Terraform; reading the state requires both.
- **Azure Storage (`azurerm` backend):** storage accounts encrypt data at rest. Restrict access to the container
  with Azure RBAC and avoid shared account keys.
- **HCP Terraform / Terraform Enterprise:** state is encrypted at rest. Limit the workspace *state versions*
  permissions to the people and teams who need them.

```terraform
terraform {
  backend "s3" {
    bucket       = "example-terraform-state"
    key          = "certificates/web.tfstate"
    region       = "us-east-1"
    encrypt      = true
    kms_key_id   = "arn:aws:kms:us-east-1:111122223333:key/00000000-0000-0000-0000-000000000000"
    use_lockfile = true
  }
}
```

Also:

- Never commit `terraform.tfstate`, `*.tfstate.backup`, saved plan files or the `.terraform` directory to version
  control. Local state is stored unencrypted on disk.
- Treat everyone who can run `terraform state pull` or read the backend as someone who can read the key. Keep CI/CD
  logs free of state and plan contents.
- Enable versioning on the state bucket or container: old state versions contain the old keys as well.

## Key export policies

Generating the key with `tls_private_key` means the key exists outside a key store: in Terraform's memory, in state,
and in every destination. **This conflicts with security policies that forbid exporting or copying private keys**,
for example a policy that keys must be generated and kept in an HSM. Encrypting the state does not change this.

If such a policy applies, generate the key and the CSR where the policy allows (for example on the server or in the
HSM that uses the key), pass only the CSR to Terraform, and do not deliver the key through Terraform:

```terraform
resource "certsecure_certificate" "app" {
  csr_pem  = file("${path.module}/app.csr")
  ca_name  = "Issuing-CA-01"
  template = "WebServer"
}
```

A CSR and a certificate are public data; state then holds no secret from this configuration.

## Keeping the key out of state with write-only arguments

Terraform 1.11 and later support *write-only* arguments: values that are sent to the provider during apply but never
stored in the plan or state. Several resources used with CertSecure accept the private key as a write-only argument:

| Resource               | Write-only arguments                                   | Provider version |
|------------------------|--------------------------------------------------------|------------------|
| `tls_cert_request`     | `private_key_pem_wo`, `private_key_pem_wo_version`     | hashicorp/tls 4.4.0 and later |
| `aws_acm_certificate`  | `private_key_wo`, `private_key_wo_version`             | hashicorp/aws 6.47.0 and later |
| `kubernetes_secret_v1` | `data_wo`, `data_wo_revision`                          | hashicorp/kubernetes 2.36.0 and later |

A write-only argument only keeps the key out of state if the value itself does not come from state, so
`tls_private_key.app.private_key_pem` cannot be used. The key must come from an *ephemeral* source, such as an
ephemeral input variable (Terraform 1.10 and later) or an ephemeral resource that reads the key from a secret store.

~> **Use a key that stays the same between runs.** The key must be supplied on every apply: for example
`aws_acm_certificate` re-imports the renewed certificate with the key from `private_key_wo`. The ephemeral
`tls_private_key` resource generates a **new key on every run**, so it does not match the issued certificate on the
next run. Use it only for keys that are used once.

The following example takes the key from an ephemeral variable, set for example from a secret store in the
pipeline (`TF_VAR_private_key_pem`). The key is generated outside Terraform, and no state file holds it:

```terraform
variable "private_key_pem" {
  type      = string
  sensitive = true
  ephemeral = true
}

# Increase when the key is rotated: the CSR and the ACM import then use the new key.
variable "key_version" {
  type    = number
  default = 1
}

resource "tls_cert_request" "web" {
  private_key_pem_wo         = var.private_key_pem
  private_key_pem_wo_version = var.key_version

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
  private_key_wo         = var.private_key_pem
  private_key_wo_version = var.key_version
  certificate_body       = certsecure_certificate.web.certificate_pem
  certificate_chain      = certsecure_certificate.web.chain_pem
}
```

Things to know:

- **Every plan and apply needs the key.** Supply `var.private_key_pem` on each run, also when applying a saved plan.
- **Key rotation.** Put the new key in the secret store and increase `key_version`. The CSR changes, so
  `certsecure_certificate` renews with the new key, and ACM imports the new certificate with it.
- **Kubernetes secrets.** `kubernetes_secret_v1` sends `data_wo` only when `data_wo_revision` changes, and replaces
  the secret's data on every update. Put both `tls.crt` and `tls.key` in `data_wo`, never the certificate in `data`
  and the key in `data_wo` (an update of `data` alone removes the key from the secret), and set
  `data_wo_revision = certsecure_certificate.web.enrollment_id`: the enrollment ID changes with every new or renewed
  certificate, so the secret is updated with it.
- **Destinations without a write-only argument** still store the key in state. For example,
  `azurerm_key_vault_certificate` needs the key in `certificate.contents`. Check the destination provider's
  documentation for write-only arguments, and protect the state as described above.
