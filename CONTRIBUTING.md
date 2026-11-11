# Developing the CertSecure Provider for Terraform

Thank you for your interest in contributing to the CertSecure provider. Here you'll find information to help you get
started with provider development. The best place to get started with the development of Terraform providers is the
[Terraform Plugin Framework documentation](https://developer.hashicorp.com/terraform/plugin/framework).

## How to contribute

* **Open an issue first** for anything larger than a small fix, so the approach can be agreed before you write code.
* **Tests are required.** Every behavior change needs unit tests against the in-memory CertSecure server (see
  [Unit tests](#unit-tests)). Contributors do not need access to a CertSecure deployment.
* **Acceptance tests are run by the maintainers.** Before merging, a maintainer runs the acceptance tests against a lab
  CertSecure deployment when the change needs them.
* **Add a CHANGELOG entry** under `# Unreleased` in [CHANGELOG.md](CHANGELOG.md) for every user-visible change.
* **Review and merge.** A maintainer reviews and approves every pull request; CI must pass. Workflows for pull requests
  from first-time contributors start after a maintainer approves them. Pull requests are merged with merge commits.
* **Security issues** are never reported in public issues or pull requests; see [SECURITY.md](SECURITY.md).

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

Releases are made by the maintainers.

1. Move the `# Unreleased` entries in [CHANGELOG.md](CHANGELOG.md) under a `# vX.Y.Z` heading.
2. Run `./tag.sh vX.Y.Z` on an up-to-date, clean `main`. It checks the tag format and the changelog, then creates and
   pushes the tag. Only maintainers can create `v*` tags.
3. The `Release` workflow runs in the protected `release` environment and waits for a maintainer's approval. It then
   builds with GoReleaser and publishes a GitHub release with the zip archives, `SHA256SUMS`, its detached GPG
   signature, and the registry manifest. The signing key is stored only in that environment.
4. The Terraform Registry publishes the new version from the GitHub release.
