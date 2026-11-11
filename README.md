# CertSecure Terraform Provider

## Overview

The Terraform provider for [CertSecure Manager](https://www.encryptionconsulting.com/) enables certificate issuance
through CertSecure with HashiCorp Terraform. The provider is a client of the CertSecure REST API only; CertSecure
reaches the certificate authority through its connectors:

```
Terraform → terraform-provider-certsecure → CertSecure API → CertSecure connector → CA (e.g. Microsoft CA / AD CS)
```

Below are the currently supported resources and data sources:

| CertSecure Resource         | CertSecure API                          | Terraform Resource                                                                     |
|-----------------------------|-----------------------------------------|----------------------------------------------------------------------------------------|
| Certificate (CSR enrollment) | `POST /enrollment/enroll_csr`           | [certsecure_certificate](docs/resources/certificate.md) (resource)                     |
| Available CAs               | `GET /available_ca`                     | [certsecure_cas](docs/data-sources/cas.md) (data source)                               |
| CA templates                | `GET /enrollment/templates`, `GET /template/ca` | [certsecure_templates](docs/data-sources/templates.md) (data source)          |
| Certificate lookup          | `GET /enrollment/enrolled_csr_details`, downloads | [certsecure_certificate](docs/data-sources/certificate.md) (data source)     |

The full API reference of a deployment is available at `<CERTSECURE_URL>/static/swagger.json`.

## Support

The CertSecure Terraform provider is developed and supported by Encryption Consulting for CertSecure Manager
customers. For help with the provider, contact Encryption Consulting through your usual support channel or the
[contact page](https://www.encryptionconsulting.com/contact-us/).

You can also report a problem or suggest a new feature in [Issues](../../issues). If you want to contribute bug fixes
or proposed enhancements, see the [Contributing Guidelines](CONTRIBUTING.md) and create a [Pull request](../../pulls).
Report security vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).

## Authentication

The provider authenticates with a CertSecure API token, sent as `Authorization: Bearer <token>`. Tokens are created
in CertSecure (API Token Management) and are not managed by this provider. The token's role determines which CAs and
templates it can use. The token is validated when the provider is configured.

```terraform
provider "certsecure" {
  url   = "https://certsecure.example.com"
  token = var.certsecure_token
}
```

Environment variables: `CERTSECURE_URL`, `CERTSECURE_TOKEN`, `CERTSECURE_CA_BUNDLE`. Attributes set in the provider
block override environment variables.

## Usage

* [Documentation](docs/index.md)
* Examples
    * [Certificate Resource](docs/resources/certificate.md)
    * [CAs Data Source](docs/data-sources/cas.md)
    * [Templates Data Source](docs/data-sources/templates.md)
* [Contributing](CONTRIBUTING.md)
* [License](LICENSE)

```terraform
terraform {
  required_providers {
    certsecure = {
      source = "encryption-consulting-llc/certsecure"
    }
  }
}

provider "certsecure" {
  url = "https://certsecure.example.com"
  # token from CERTSECURE_TOKEN
}

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
  csr_pem  = tls_cert_request.app.cert_request_pem
  ca_name  = "Issuing-CA-01"
  template = "WebServer"
}
```

Key behaviors (details in the [resource documentation](docs/resources/certificate.md)):

* A new `csr_pem`, or reaching the `early_renewal_hours` window, renews the certificate in place; other argument
  changes issue a new certificate.
* Destroy revokes the certificate only with `revoke_on_destroy = true` (default `false`).
* Templates that require approval are supported. A renewal that awaits approval resumes on the next `apply`; a new
  certificate that awaits approval resumes after `terraform untaint` (otherwise Terraform replaces it and submits a
  new request). Errors include the enrollment ID and task ID.

## Compatibility

| CertSecure Manager Version | Terraform Provider Version |
|----------------------------|----------------------------|
| 3.4                        | 1.0.x, 1.1.x               |

## Requirements

* [Terraform](https://developer.hashicorp.com/terraform/install) 1.0 or later
* [Go](https://go.dev/doc/install) (version in [`go.mod`](go.mod)), only to build the provider
* [CertSecure Manager](https://www.encryptionconsulting.com/) (see compatibility table)
    * A CertSecure API token whose role may submit CSRs to the CAs and templates you use

## Install

### From the Terraform Registry

The provider is installed automatically by `terraform init`:

```terraform
terraform {
  required_providers {
    certsecure = {
      source  = "encryption-consulting-llc/certsecure"
      version = "~> 1.0"
    }
  }
}
```

### From GitHub

Download a pre-built release and install it into Terraform's local filesystem mirror.

1. Download the release archive for your platform from the [releases page](../../releases).
2. Unzip the archive.
3. Move the binary to Terraform's implicit local mirror directory. The path must match the pattern:

**Linux / macOS**
```
~/.terraform.d/plugins/registry.terraform.io/encryption-consulting-llc/certsecure/<VERSION>/<OS>_<ARCH>/terraform-provider-certsecure_v<VERSION>
```

Example for Linux amd64, version 1.1.0:
```bash
PROVIDER_VERSION="1.1.0"
OS_ARCH="linux_amd64"                  # or linux_arm64 / darwin_amd64 / darwin_arm64
PLUGIN_DIR="${HOME}/.terraform.d/plugins/registry.terraform.io/encryption-consulting-llc/certsecure/${PROVIDER_VERSION}/${OS_ARCH}"
mkdir -p "${PLUGIN_DIR}"
mv terraform-provider-certsecure_v${PROVIDER_VERSION} "${PLUGIN_DIR}/"
chmod +x "${PLUGIN_DIR}/terraform-provider-certsecure_v${PROVIDER_VERSION}"
```

**Windows (PowerShell)**
```powershell
$ProviderVersion = "1.1.0"
$OSArch = "windows_amd64"              # or windows_arm64
$PluginDir = "$env:APPDATA\terraform.d\plugins\registry.terraform.io\encryption-consulting-llc\certsecure\$ProviderVersion\$OSArch"
New-Item -ItemType Directory -Force -Path $PluginDir
Move-Item "terraform-provider-certsecure_v$ProviderVersion.exe" "$PluginDir\"
```

4. Use the standard registry source with the exact version; `terraform init` finds the local binary:

```terraform
terraform {
  required_providers {
    certsecure = {
      source  = "encryption-consulting-llc/certsecure"
      version = "1.1.0"
    }
  }
}
```

### From source

See [CONTRIBUTING.md](CONTRIBUTING.md) (`make install-local`).

## CertSecure Permissions

The CertSecure user that owns the API token needs the following permissions.

### Resources

#### resource "certsecure_certificate"

| Operation                         | Permissions                                                                                                              |
|-----------------------------------|--------------------------------------------------------------------------------------------------------------------------|
| Issue (create)                    | Access to the CA and template through the user's role and department, and *View Enrollment Database* to follow the request and download the certificate. The user owns the certificates it requests, so it can download them. |
| Renew (update)                    | *Renew Inventory Certificates*, or owner or watcher of the certificate, and *View Enrollment Database*.                  |
| Revoke (`revoke_on_destroy`)      | Owner of the certificate, department PKI admin for its CA, or global admin, and *View Enrollment Database*.              |
| Skip approval                     | Requests that the template's approval workflow or a policy flags wait for approval, unless the user has *Bypass Certificate Approval*. |

### Data Sources

#### data "certsecure_certificate"

*View Enrollment Database*.

#### data "certsecure_cas" and data "certsecure_templates"

No specific permission: a valid API token.

## Contributing

Contributions are welcome. See the [Contributing Guidelines](CONTRIBUTING.md) for the development setup, tests and
the release process.

## License

Licensed under the [Apache License 2.0](LICENSE).
