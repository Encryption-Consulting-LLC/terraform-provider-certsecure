# Developing the CertSecure Provider for Terraform

Thank you for your interest in contributing to the CertSecure provider. Here you'll find information to help you get
started with provider development. The best place to get started with the development of Terraform providers is the
[Terraform Plugin Framework documentation](https://developer.hashicorp.com/terraform/plugin/framework).

## Building the provider

1. Clone the repository
    ```shell
    git clone https://github.com/Encryption-Consulting-LLC/terraform-provider-certsecure.git
    cd terraform-provider-certsecure
    ```
2. Build the provider
    ```shell
    make build
    ```

## Development environment

* [Go](https://go.dev/doc/install), at the version in [`go.mod`](go.mod)
* [Terraform](https://developer.hashicorp.com/terraform/install) CLI, for docs generation and tests
* [golangci-lint](https://golangci-lint.run/) v2, for `make lint`

Useful targets:

| Target                | Purpose                                                                                       |
|-----------------------|-----------------------------------------------------------------------------------------------|
| `make build`          | Check formatting and build                                                                    |
| `make install-local`  | Install the binary into `~/.terraform.d/plugins` so `terraform init` uses it (version `VERSION`) |
| `make fmt` / `make fmtcheck` | Format / check formatting of Go code                                                   |
| `make lint`           | Run golangci-lint                                                                             |
| `make test`           | Unit tests                                                                                    |
| `make testacc`        | Acceptance tests against a real CertSecure (issues real certificates)                         |
| `make generate`       | Format examples and regenerate `docs/` with tfplugindocs                                      |
| `make docs-validate`  | Validate `docs/` against the provider schema                                                  |

### Debugging

The provider supports debuggers such as delve. Run the binary with `-debug`, then export the printed
`TF_REATTACH_PROVIDERS` value in the shell where you run Terraform. Alternatively, use a
[`dev_overrides`](https://developer.hashicorp.com/terraform/cli/config/config-file#development-overrides-for-provider-developers)
block for `encryption-consulting-llc/certsecure` pointing at your `$GOPATH/bin`.

Set `TF_LOG=DEBUG` to see each CertSecure API request (method, path, status, duration). Tokens and the
`Authorization` header are never logged.

## Code layout

* `main.go`: provider server entry point; the registry address is defined here.
* `internal/client`: typed CertSecure REST API client with no Terraform dependencies. The CertSecure API uses different
  identifier spellings across endpoints (`eid`, `EnrollmentID`, `taskID`, `serialNum`, `number`), so every endpoint has its
  own explicit method. Unit-tested with `httptest` and the redacted fixtures in `internal/client/testdata`
  (see its README).
* `internal/provider`: provider, resources, and data sources.
* `examples/` and `templates/`: inputs for tfplugindocs. `docs/` is generated; never edit it by hand.

### CertSecure API notes

The swagger at `/static/swagger.json` differs from the live API in places; the client follows the live API:

* `POST /enrollment/enroll_csr` is asynchronous and returns only `{"TaskID": "..."}`. The enrollment ID is found via
  `GET /tasks?taskID=` and `GET /enrollment/enrolled_csr_details?taskID=`. It must never be retried automatically.
* `san_attributes` must be a list of strings such as `"dns=a.example.com"` and `"ipaddress=192.0.2.1"`; `email` must be a list.
* `GET /enrollment/download_cert` takes `eid`; the chain comes from `GET /enrollment/download?eid=&type=p7b`, which may
  label the PKCS#7 bundle as `CERTIFICATE`.
* `GET /enrollment/view-trust-chain` returns metadata only, not certificates.
* `GET /inventory/templates?ca=` answers HTTP 500 for CAs without templates; use `GET /enrollment/templates`.

## Tests

### Unit tests

```shell
make test
```

Resource and data source tests run the real Terraform CLI against an in-memory fake CertSecure
(`internal/provider/fake_certsecure_test.go`). terraform-plugin-testing uses the `terraform` binary from `PATH`, or
`TF_ACC_TERRAFORM_PATH`, or downloads one.

### Acceptance tests

Acceptance tests run against a real CertSecure deployment and **issue real certificates**, which are not revoked.

```shell
make testacc
```

The following environment variables must be set:

* `CERTSECURE_URL`: base URL of the CertSecure API.
* `CERTSECURE_TOKEN`: API token. Should be a secret.
* `CERTSECURE_TEST_CA`: CA name. The CA must exist in CertSecure and have `CERTSECURE_TEST_TEMPLATE`.
* `CERTSECURE_TEST_TEMPLATE`: template name. It must issue without approval, and the token's role must be allowed to
  submit CSRs with it.

In CI, acceptance tests run only from the manually triggered `Acceptance Tests` workflow using the protected
`acceptance` environment, never for pull requests.

### Test data hygiene

Never commit tokens, deployment URLs, internal host names, real email addresses, or customer names. Fixtures must be
redacted (see `internal/client/testdata/README.md`); tests and examples read `CERTSECURE_URL` instead of hard-coding
endpoints.

## Documentation

Every schema attribute needs a `MarkdownDescription`. Resource and data source pages are rendered from
`templates/` and `examples/` by tfplugindocs:

```shell
make generate
make docs-validate
```

CI fails if `make generate` changes any committed file.

## Releasing

1. Add a section for the version to [CHANGELOG.md](CHANGELOG.md).
2. Run `./tag.sh vX.Y.Z` on an up-to-date, clean `main`. It checks the tag format and the changelog, then creates and
   pushes the tag.
3. The `Release` workflow builds with GoReleaser and publishes a GitHub release with the zip archives,
   `SHA256SUMS`, its detached GPG signature, and the registry manifest. The Terraform Registry picks up new releases
   through its GitHub webhook.

Repository secrets required for releases: `GPG_PRIVATE_KEY` (ASCII-armored private RSA key) and `PASSPHRASE`.

### Publishing to the Terraform Registry

The registry only publishes from a **public** GitHub repository named `terraform-provider-certsecure`. The registry
namespace is the lowercased GitHub organization name. Before the first public release:

1. Decide the public organization. If it differs from `Encryption-Consulting-LLC`, update the namespace everywhere it
   appears:
    * `go.mod` module path, and the import paths in Go files
    * `main.go` provider address (`registry.terraform.io/<namespace>/certsecure`)
    * `source = "<namespace>/certsecure"` in `examples/`, `templates/`, `README.md`, and this file
    * the plugin directory paths in `README.md` and `GNUmakefile` (`NAMESPACE`)
2. Make the repository public (or push a clean-history copy to the public repository).
3. Generate an RSA GPG key for signing, store it in the `GPG_PRIVATE_KEY` / `PASSPHRASE` secrets, and add the public key to
   the organization's namespace in the [Terraform Registry](https://registry.terraform.io/settings/gpg-keys).
4. Sign in to the [Terraform Registry](https://registry.terraform.io/publish/provider) with GitHub, choose the
   organization, and publish the repository.
5. Tag the first release (`v1.0.0`) with `./tag.sh`.
