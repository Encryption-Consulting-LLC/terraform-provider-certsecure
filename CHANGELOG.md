# v1.2.1

## Certificates

### Documentation

- docs: new guide "Protecting the Private Key in Terraform State": which resources store the private key in state,
  how to protect the state, the conflict with key export policies, and keeping the key out of state with write-only
  arguments (`tls_cert_request`, `aws_acm_certificate`, `kubernetes_secret_v1`).
- docs: delivery guides with complete configurations for AWS Certificate Manager (with an Application Load Balancer
  listener), Azure Key Vault (PEM import) and Kubernetes (TLS secret for an Ingress): how renewal, key rotation,
  replacement and revocation reach each destination. The provider overview lists the guides.
- docs: the AWS Certificate Manager guide notes that `aws_acm_certificate.not_after` can show the previous expiry
  date until the next run after a renewal.
- docs: import with an `import` block, finding the enrollment ID from a serial number with the `certsecure_certificate`
  data source, and which settings the first apply after an import records.
- docs: README links the certificate data source and the guides; the install example uses `~> 1.2`.
- docs: new troubleshooting guide: connection and authentication errors, requests refused by CertSecure, approvals,
  timeouts, downloads, destroy warnings and data source lookups, each with what to do and what the next apply does.

# v1.2.0

## Certificates

### Features

- feat: data source `certsecure_certificate` can look up a certificate by `serial_number` and `ca_name` instead of
  `enrollment_id`. The serial number may be upper or lower case, with or without colons. `enrollment_id` is now
  optional and filled in by the lookup.
- feat: new `certsecure_certificate` argument `wait_for_approval` (default `false`). When `true`, an apply whose new
  certificate or renewal awaits approval in CertSecure waits until it is approved and issued, denied, or the `create`
  (`update` for renewals) timeout expires, so an approval within the timeout needs no `terraform untaint`.

# v1.1.0

## Certificates

### Features

- feat: new data source `certsecure_certificate` reads an existing certificate by enrollment ID: certificate, chain,
  status, CA, template, common name, DNS names, tags, serial number and validity period. It never issues, renews or
  revokes.

### Bug Fixes

- fix: `certsecure_cas` explains an HTTP 401 for a token that passed the provider's token check, and points to API
  tokens created in API Token Management.

### Documentation

- docs: the provider docs title is now "CertSecure Provider".
- docs: support statement (the provider is supported by Encryption Consulting for CertSecure Manager customers),
  security policy (`SECURITY.md`), issue templates, and contribution guidelines.

# v1.0.0

## Certificates

### Features

- feat: new resource `certsecure_certificate` issues a certificate from a CSR through CertSecure (Microsoft CA), with
  optional subject alternative names, owner email, tags, and notes. Outputs the certificate, the issuer-first chain,
  the serial number, and the validity period. Supports import by enrollment ID.
- feat: `certsecure_certificate` renews in place through CertSecure's renew-with-CSR API when `csr_pem` changes
  (same key or a new key) or when the certificate expires within the new `early_renewal_hours` window. CertSecure
  never generates or stores a private key. A renewal that awaits approval or times out is recorded in the new
  `pending_renewal_task_id` attribute and resumed by the next apply instead of being submitted again. Adds an `update`
  timeout.
- feat: new `certsecure_certificate` argument `revoke_on_destroy` (default `false`) revokes the certificate in
  CertSecure when the resource is destroyed or replaced, and waits until the revocation completes. Certificates that
  are already revoked, expired, or pending are not revoked. Adds a `delete` timeout.
- feat: a new `certsecure_certificate` whose creation awaits approval, times out, or fails to download is saved in
  state with its enrollment ID and task ID. After `terraform untaint`, the next apply resumes that request in place
  instead of submitting a new one. A request that was denied or failed, or whose `csr_pem` changed, is replaced.

## Certificate Authorities

### Features

- feat: new data source `certsecure_cas` lists the CAs the token may enroll from, optionally filtered by type.
- feat: new data source `certsecure_templates` lists the templates available on a CA.
