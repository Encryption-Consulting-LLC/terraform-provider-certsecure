---
page_title: "Troubleshooting"
subcategory: ""
description: |-
  Common CertSecure provider errors and warnings, what they mean, and what the next apply does.
---

# Troubleshooting

This guide lists the errors and warnings of the CertSecure provider by the summary Terraform prints, what they mean,
and what to do.

## Before you start

- **Errors identify the request.** Once a request reaches CertSecure, errors include its enrollment ID (eid) and task
  ID, for example `Request: enrollment ID (eid) 1501, task ID 20001.` Search for them in CertSecure to approve, deny,
  download or revoke the request there.
- **Debug logging.** Set `TF_LOG=DEBUG` to log every CertSecure API request (method, path, status, duration). Tokens
  and the `Authorization` header are never logged.
- **Permissions.** Most refusals come from the role of the API token's user. The
  [README](https://github.com/Encryption-Consulting-LLC/terraform-provider-certsecure#certsecure-permissions) lists the
  permissions for each operation.

## Connecting and authenticating

| Message | Cause and fix |
|---|---|
| `Missing CertSecure URL` / `Missing CertSecure token` | Set `url` and `token` in the provider block, or `CERTSECURE_URL` and `CERTSECURE_TOKEN`. |
| `Unable to authenticate to CertSecure: CertSecure token missing, invalid, or expired.` | CertSecure refused the token (HTTP 401) when the provider was configured. Create a new API token in CertSecure (API Token Management) and set it. |
| `Unable to authenticate to CertSecure: CertSecure request failed.` with a TLS error such as `x509: certificate signed by unknown authority` in the details | The CertSecure server certificate is issued by a CA your system does not trust. Set `ca_bundle_pem` or `CERTSECURE_CA_BUNDLE` to the CA certificates in PEM format. `insecure_skip_verify` is for lab use only. |
| `CertSecure request failed.` with `context deadline exceeded` or `Client.Timeout` | A single HTTP request took longer than `request_timeout` (default `60s`). Check the network path to CertSecure, or raise `request_timeout`. |
| `Error listing CertSecure CAs: ...` saying that CertSecure accepted the token but refused it for the CA list | The CA list endpoint refused this token. Use an API token created in CertSecure (API Token Management). |

## Requests refused by CertSecure

| Message | Cause and fix |
|---|---|
| `... Token lacks permission for this CA/template.` | HTTP 403. The token's user has no access to the CA or template through its role and department, or lacks the permission for the operation. See the README permissions table. |
| `... CertSecure rejected the request: <message>` | HTTP 400. CertSecure explains the problem in the message, for example a CA name that is not registered or a template that is not available for the CA. Check `ca_name` and `template` with the `certsecure_cas` and `certsecure_templates` data sources. |
| `Error submitting certificate renewal: ...` with HTTP 409 in the details | Only active and expired certificates can be renewed. A revoked certificate cannot: issue a new one with `terraform apply -replace=<address>`. |
| `Certificate request failed in CertSecure` | The request ended in an error in CertSecure, for example denied by a policy or by the CA. The details contain CertSecure's reason. Fix the cause; the next apply submits a new request. |

## Approval

| Message | Cause and fix |
|---|---|
| `Certificate request requires approval` (new certificate) | The template or a policy requires approval. The request is saved in state and Terraform marks the resource as tainted. Approve it in CertSecure, then run `terraform untaint <address>` and `terraform apply`: the apply resumes the same request and does not submit a new one. Without `untaint`, the next apply replaces the resource and submits a **new** request. |
| `Certificate request requires approval` (renewal) | The renewal is recorded in `pending_renewal_task_id`, and the previous certificate stays in state and in use. Approve or deny it in CertSecure, then run `terraform apply` again (no `untaint` needed). After a denial, the next apply submits a new renewal. |
| `Timed out waiting for approval` | `wait_for_approval = true` and nobody approved within the `create` (or `update`) timeout. Continue as above, or raise the timeout. |
| `A renewal for a different CSR is still pending` | `csr_pem` changed while a renewal for the previous CSR awaits approval. Approve or deny that renewal in CertSecure, or restore the previous CSR, then apply again. |
| `Pending renewal task no longer exists` | The renewal task recorded in state is gone from CertSecure. Run `terraform apply` again: it submits a new renewal. |

To let the apply wait for approvals instead of failing, set `wait_for_approval = true` with a long enough timeout; see
the [resource documentation](https://registry.terraform.io/providers/encryption-consulting-llc/certsecure/latest/docs/resources/certificate#approval-and-resuming-a-new-certificate).

## Timeouts

CertSecure processes requests asynchronously. The provider waits up to the `create` timeout for a new certificate,
the `update` timeout for a renewal and the `delete` timeout for a revocation (all 5 minutes by default). Raise them
for slow CAs:

```terraform
resource "certsecure_certificate" "app" {
  # ...
  timeouts {
    create = "15m"
    update = "15m"
    delete = "15m"
  }
}
```

| Message | What the next apply does |
|---|---|
| `Timed out waiting for certificate issuance` (new certificate) | The request is saved in state and the resource is tainted. Run `terraform untaint <address>` and `terraform apply` to keep waiting for the same request; without `untaint`, a new request is submitted. |
| `Timed out waiting for certificate issuance` (renewal) | The renewal is recorded in `pending_renewal_task_id`; the next `terraform apply` keeps waiting for it. |
| `Timed out waiting for certificate revocation` | Destroy failed and the certificate stays in state. Running destroy again checks the certificate first and does not revoke it twice. |

## Certificates and downloads

| Message | Cause and fix |
|---|---|
| `Certificate issued but could not be downloaded: ...` | The certificate exists in CertSecure, but the download failed. The request is saved in state; resume it with `terraform untaint <address>` and `terraform apply`, or download or revoke the certificate in CertSecure. |
| `Downloaded certificate does not match the CSR` | The certificate CertSecure returned is not for the CSR's key. The next apply submits a new request. Revoke the returned certificate in CertSecure if it is not needed. |
| `Invalid CSR` | `csr_pem` is not a PEM-encoded certificate signing request, or its signature is invalid. |

## Destroy

| Message | Meaning |
|---|---|
| `Certificate was NOT revoked` (revoke_on_destroy is not set) | `revoke_on_destroy` is `false` (the default), so destroy only removed the certificate from state. It is still valid; revoke it in CertSecure if it is no longer needed. To revoke on destroy, apply `revoke_on_destroy = true` before destroying. |
| `Certificate was NOT revoked` (status in CertSecure) | Only active certificates can be revoked. The certificate is already revoked or expired, or no longer in CertSecure; it is removed from state. |
| `Certificate request was NOT cancelled` | The resource had a request without a certificate (for example awaiting approval). Destroy removes it from state only; deny the request in CertSecure, or revoke the certificate there if it was issued meanwhile. |
| `Pending renewal was not cancelled` | A renewal was still open. If it is approved later, its certificate is not managed by Terraform; deny it in CertSecure if it is not needed. |
| `Certificate revocation failed in CertSecure` | CertSecure could not revoke the certificate; the details contain the reason. The certificate is still active and in state; running destroy again submits a new revocation. |
| `Error revoking certificate: ... Token lacks permission for this CA/template.` | Only the certificate's owner, a department PKI admin for its CA, or a global admin can revoke it. |

## Looking up certificates (data source)

| Message | Cause and fix |
|---|---|
| `Certificate not found` | No certificate with this `enrollment_id`, or with this `serial_number` on this `ca_name`. The serial number may be given in upper or lower case, with or without colons. |
| `Certificate not enrolled through CertSecure` | The certificate is in the CertSecure inventory (for example discovered on a server) but was not enrolled through CertSecure, so it has no enrollment ID and cannot be read. |
| `... CertSecure rejected the request: <ca> - is not a registered CA.` | `ca_name` is not a CA registered in CertSecure. List the CAs with the `certsecure_cas` data source. |

## Renewal did not happen

- **Renewal only runs when Terraform runs.** Nothing renews certificates between runs. Run `terraform apply` on a
  schedule with an `early_renewal_hours` window that covers missed runs.
- **`early_renewal_hours` defaults to `0`.** Without it, a certificate is renewed only when `csr_pem` changes.
- **A destination shows the old expiry date.** After a renewal, `aws_acm_certificate.not_after` can lag by one run;
  see the [AWS Certificate Manager guide](https://registry.terraform.io/providers/encryption-consulting-llc/certsecure/latest/docs/guides/aws-acm).
