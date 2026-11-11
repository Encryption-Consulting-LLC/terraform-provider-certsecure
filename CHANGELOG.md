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
