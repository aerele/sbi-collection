# SBI UAT API contract

The bank's `Collection_API_Integration_Document_for_VAN_based_Collection_Hosted.pdf`
(crypto on pages 2–4; APIs on pages 5–10) defines the integration. The latest UAT
email messages supplied with this change override conflicting PDF examples.

All three callbacks use POST:

- `/api/method/sbi_collection.api.authenticate`
- `/api/method/sbi_collection.api.dealer_validation`
- `/api/method/sbi_collection.api.transaction_post` (SBI calls this MIS)

## Transport and encryption

Recognized business outcomes return HTTP 200. A verified/decrypted request receives
an encrypted response, including invalid credentials, missing/invalid/expired tokens,
unknown VANs, and rejected amounts. Token checks run after envelope verification and
before customer lookups or Payment Entry creation. Dealer failures echo the decrypted
`request_id`, or use an empty string when absent.

Malformed/unverifiable envelopes return a controlled plaintext `status_code: "01"`
failure. Missing/unusable configured keys or an inability to encrypt a response also
produce a controlled plaintext failure. Exception details are not returned. A scoped
`after_request` hook normalizes HTTP 417 JSON parsing failures that Frappe rejects
before dispatching these SBI POST routes. Other routes and unrelated middleware or
infrastructure errors keep their normal HTTP behavior.

The existing Frappe v1 method transport wraps the returned object in `message`:

```json
{"message":{"data":"...","hash_digest":"...","session_key":"..."}}
```

The response tables below describe the plaintext **inside** the encrypted envelope.
Plain failure responses use the same Frappe outer `message` wrapper.

Crypto is unchanged: AES-256-GCM with a fresh 256-bit session key per message and a
fixed 16-byte zero IV; RSA-OAEP SHA1/MGF1-SHA1 for session-key encryption;
SHA256withRSA over encrypted data. Client Private Key holds our private PEM key;
SBI Public Key holds SBI's public PEM key. This change does not update keys,
certificates, settings data, or database records.

Raw JSON bodies are parsed even when `get_json()` rejects the client's Content-Type
or returns no parsed value. Invalid or empty bodies fail safely. Authentication
plaintext is accepted only when Enable Encryption is explicitly disabled. An
envelope submitted in development mode still receives an encrypted reply.

Request logs are redacted, and issued tokens are redacted in response logs. UAT
diagnostics remain enabled in Error Log under `SBI Auth Debug`,
`SBI Dealer Validation Debug`, `SBI Transaction Post Debug`, and
`SBI Request Parsing Debug`. These record processing stages, parsing fallback,
credential presence/match booleans, token rejection, exception types/locations, and
response status/encryption. They exclude credential/token values, raw bodies,
exception messages, and traceback locals in the diagnostic message. Diagnostics use
`frappe.log_error(title=..., message=...)`, with form fields temporarily redacted
while Frappe gathers request metadata, then restored. Frappe's standard logging and
site telemetry behavior applies; logging failures cannot break responses.
Caught Frappe validation messages are still removed from the response's plaintext
message queue; this does not delete saved Error Log records.

Before production, review this temporary logging and set
`UAT_DIAGNOSTICS_ENABLED = False` in `utils/diagnostics.py`. This is a code switch;
no existing Settings data or database records are modified to enable it.

## Response plaintext

| API / outcome | status_code | message | Other fields |
| --- | --- | --- | --- |
| Authentication success | `00` | `Login Successful` | `token`: JWT |
| Invalid/missing credentials | `01` | `Invalid Credential` | None |
| Dealer success | `00` | `Success` | `request_id`: incoming value or `""` |
| Dealer invalid VAN | `01` | `Invalid Van` | `request_id` |
| Dealer invalid token | `01` | `Invalid token` | `request_id` |
| Dealer negative amount | `01` | `Amount Cannot be Negative` | `request_id` |
| MIS success | `00` | `Success` | None |
| MIS invalid VAN | `01` | `Invalid Van` | None |
| MIS invalid token | `01` | `Invalid token` | None |
| MIS negative amount | `01` | `Amount Cannot be Negative` | None |
| MIS zero amount | `01` | `Amount Cannot be Zero` | None |

Dealer accepts zero. Amount validation uses decimal arithmetic, rejects nonnumeric
and nonfinite values, and runs before accounting operations. Other missing mandatory
fields and processing failures return encrypted `01` failures when decryption succeeds.

Valid MIS requests retain draft, unallocated inbound Payment Entry creation. The
existing duplicate guard checks UTR (`reference_no`), company, and `docstatus < 2`
before creating another entry. This retains the existing sequential retry behavior;
it does not introduce database uniqueness or protection against concurrent duplicate
requests.

## Verification without changing site data

From the app directory, run the bench environment's Python directly:

```bash
PYTHONDONTWRITEBYTECODE=1 ../../env/bin/python -m unittest \
  sbi_collection.tests.test_uat_contract \
  sbi_collection.tests.test_crypto -v
git diff --check
```

The UAT suite uses separate, in-memory SBI and client RSA keypairs, the real Frappe
JSON parser/router/whitelist dispatcher/response serializer, and a Werkzeug HTTP
client. Settings, database access, logs, account lookups and document persistence are
mocked. Payment Entry construction and duplicate checking execute against those mocks.
No site is selected or connected. The pre-existing database-backed integration tests
have updated expectations but should only be run on a disposable test site: their
fixtures modify settings and create accounting/customer records.

Live SBI interoperability, deployed middleware/proxy behavior, and actual ERPNext
accounting insertion remain UAT checks. Confirm SBI's handling of the existing Frappe
outer `message` wrapper. Deploying the code/hook requires the normal application
reload/cache lifecycle; this implementation does not restart services or clear caches.
