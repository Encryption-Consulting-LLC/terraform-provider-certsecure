# Client test fixtures

Response bodies captured from a live CertSecure deployment (API 3.4) and
redacted: host names, email addresses, IP addresses, and organization names
are replaced with `example` values. Structure and field names are unchanged.

| File | Endpoint |
|---|---|
| `check_token.txt` | `GET /check_token` (200; body is the literal `True`) |
| `error_401_invalid.json`, `error_401_missing.json` | any authenticated endpoint, bad or missing token |
| `version.json` | `GET /version` |
| `available_ca.json` | `GET /available_ca` |
| `template_ca.json`, `template_ca_empty.json` | `GET /template/ca?ca=` (CA with templates / without) |
| `enrollment_templates.json` | `GET /enrollment/templates` |
| `enroll_csr_200.json` | `POST /enrollment/enroll_csr` (accepted; only a TaskID is returned) |
| `enroll_csr_400_invalid_csr.json` | `POST /enrollment/enroll_csr` with a malformed CSR |
| `enroll_csr_400_generic.json` | `POST /enrollment/enroll_csr` with `san_attributes` sent as an object |
| `task_processing.json`, `task_ok.json`, `task_404.json` | `GET /tasks?taskID=` |
| `enrolled_csr_details*.json` | `GET /enrollment/enrolled_csr_details` (issued, pending, with SANs, 404; by serial for a certificate known only from the CA inventory) |
| `view_trust_chain.json` | `GET /enrollment/view-trust-chain?eid=` |
| `download_cert_400.json`, `download_400_type.json` | download endpoints with missing/unsupported parameters |
| `inventory_cert_details*.json` | `GET /inventory/cert_details` (found / 404) |

Synthesized from the CertSecure backend source rather than captured, because
the test token bypasses approvals and has full permissions:

- `task_pending_approval.json`: a task waiting for CA manager approval.
- `task_error.json`: a task denied by the policy module.
- `enroll_csr_403.json`: a token without the "Submit CSR" permission.

Certificates are never stored here; tests generate a synthetic CA chain at run time.
