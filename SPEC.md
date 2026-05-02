# Attestation as Warranty — Normative Specification

**Patent reference:** USPTO Provisional 64/055,601, claim C18
**Status:** Layer C reference. Wire format normative; production-grade hardening is Layer B.
**Author:** Stephen A. Rotzin, pro se
**Date:** 2026-05-02

---

## 1. Purpose

Cryptographic signatures prove that a message was signed by a specific key.
They do not prove that the signer stands behind the statement or accepts
consequences if the statement turns out to be false. A warranty adds that
missing layer: it is an attestation in which the issuing agent explicitly
accepts accountability for the truth of a claim within a defined scope and
time window.

The Attestation as Warranty primitive (hereafter "Warranty") solves two
related problems:

1. **Issuing a warranty:** An agent signs a structured claim, specifying the
   scope of the claim, an optional expiry, and an optional stake (a declared
   forfeiture commitment if the claim is disproven within scope). The issuer
   receives a signed warranty receipt.

2. **Recording a breach:** Any party that believes a warranty has been violated
   can submit a breach report. The breach record is associated with the original
   warranty and is itself signed by the issuer. The warranty's breach status
   becomes part of its verifiable record.

Warranties are designed for use in agentic systems where one agent must make
accountable representations to another — for example, a data provider warranting
that a dataset contains no PII, or a model agent warranting that its output
satisfies a stated constraint.

---

## 2. Conformance Terms

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as
described in RFC 2119.

- An **issuer** is the HiveAttest service that signs warranties and breach records.
- A **warrantor** is the agent identified by `agent_did` who makes the claim.
- A **relying party** is any system or agent that accepts and verifies warranties.
- A **breach** is a recorded assertion that a warranty's claim was false within
  its stated scope. A breach does not automatically invalidate the warranty
  receipt; it augments the record.
- A **stake** is an optional declaration by the warrantor of a forfeiture to be
  applied if a breach is proven. The Layer C reference implementation records
  the stake declaration but does not enforce forfeiture; that is a Layer B concern.

---

## 3. Wire Format

### 3.1 Issue Request

`POST /v1/attest/warranty/issue`

```json
{
  "agent_did":  "<string, required>",
  "action_id":  "<string, required>",
  "claim":      "<string, required>",
  "scope":      "<string, required>",
  "expires_at": "<ISO-8601 UTC string, optional>",
  "stake":      {
    "amount":   "<string, optional>",
    "currency": "<string, optional>",
    "terms":    "<string, optional>"
  }
}
```

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `agent_did` | string | REQUIRED | DID of the warranting agent. |
| `action_id` | string | REQUIRED | Reference to the action or manifest this warranty covers. UUID v4 RECOMMENDED. |
| `claim` | string | REQUIRED | The substantive statement being warranted. Plain English. E.g. `"Output does not contain PII as defined by GDPR Art. 4(1)"`. |
| `scope` | string | REQUIRED | Boundary within which the claim holds. E.g. `"response_id:abc123"`, `"dataset:v2.1"`, `"session:xyz"`. |
| `expires_at` | string | OPTIONAL | ISO-8601 UTC. If provided, the warranty is only valid until this time. Relying parties SHOULD reject expired warranties. |
| `stake.amount` | string | OPTIONAL | Declared forfeiture amount if breach is proven. |
| `stake.currency` | string | OPTIONAL | Currency or unit of the stake, e.g. `"USD"`, `"USDC"`. |
| `stake.terms` | string | OPTIONAL | Human-readable conditions under which the stake is forfeit. |

### 3.2 Issue Response

```json
{
  "warranty": {
    "warranty_id":  "<uuid-v4>",
    "agent_did":    "<echoed>",
    "action_id":    "<echoed>",
    "claim":        "<echoed>",
    "scope":        "<echoed>",
    "issued_at":    "<ISO-8601 UTC>",
    "expires_at":   "<ISO-8601 UTC or null>",
    "stake":        { "amount": "<string>", "currency": "<string>", "terms": "<string>" },
    "breach_status":"none",
    "signing": {
      "algorithm": "EdDSA",
      "curve":     "Ed25519",
      "key_id":    "<base64url SHA-256 of issuer public key>",
      "signature": "<base64url Ed25519 signature over JCS of signed body>"
    }
  },
  "_meta": {
    "layer":            "C",
    "production_grade": false,
    "spec_url":         "https://raw.githubusercontent.com/srotzin/hive-attestation-warranty/main/SPEC.md",
    "patent":           "USPTO 64/055,601",
    "claim":            "C18"
  }
}
```

| Field | Type | Semantics |
|-------|------|-----------|
| `warranty.warranty_id` | string (UUID v4) | Issuer-assigned globally unique identifier. |
| `warranty.breach_status` | enum | Initially `"none"`. Becomes `"alleged"` when a breach is submitted, and MAY become `"confirmed"` via out-of-band adjudication (Layer B). |
| `warranty.stake` | object or null | Null if no stake was declared. |

### 3.3 Breach Request

`POST /v1/attest/warranty/breach`

```json
{
  "warranty_id":        "<string, required>",
  "breach_description": "<string, required>",
  "evidence":           "<any JSON value, optional>"
}
```

Response:

```json
{
  "breach_record": {
    "breach_id":          "<uuid-v4>",
    "warranty_id":        "<echoed>",
    "breach_description": "<echoed>",
    "evidence_hash":      "<hex SHA-256 of JCS(evidence), or null>",
    "reported_at":        "<ISO-8601 UTC>",
    "signing": {
      "algorithm": "EdDSA",
      "curve":     "Ed25519",
      "key_id":    "<base64url SHA-256 of issuer public key>",
      "signature": "<base64url Ed25519 signature>"
    }
  },
  "_meta": { "layer": "C", "production_grade": false, "spec_url": "...", "patent": "USPTO 64/055,601", "claim": "C18" }
}
```

The breach report is appended to the warranty's record. The `warranty.breach_status`
for subsequent GET requests will reflect `"alleged"`.

### 3.4 Fetch a Warranty

`GET /v1/attest/warranty/{warranty_id}`

Returns the full warranty object including current `breach_status` and any
associated breach records:

```json
{
  "warranty":      { "...": "as issued, with current breach_status" },
  "breach_records":[ "..." ],
  "_meta":         { "layer": "C", "production_grade": false, "spec_url": "...", "patent": "USPTO 64/055,601", "claim": "C18" }
}
```

---

## 4. Cryptography

### 4.1 Algorithms

| Primitive | Algorithm | Reference |
|-----------|-----------|-----------|
| Signing | Ed25519 (EdDSA) | RFC 8032 |
| Canonicalization | JSON Canonicalization Scheme (JCS) | RFC 8785 |
| Hashing | SHA-256 | FIPS 180-4 |
| Key identifier | base64url-no-pad SHA-256 of public key bytes | — |

### 4.2 Signed Body Construction (Warranty)

The issuer signs the following object, JCS-canonicalized. Fields whose values
are `null` or absent MUST be omitted from the signed body:

```json
{
  "action_id":  "<string>",
  "agent_did":  "<string>",
  "claim":      "<string>",
  "expires_at": "<ISO-8601 UTC>",
  "issued_at":  "<ISO-8601 UTC>",
  "scope":      "<string>",
  "stake":      { "amount": "<string>", "currency": "<string>", "terms": "<string>" },
  "warranty_id":"<uuid-v4>"
}
```

```
signature = Ed25519Sign( privKey, UTF-8( JCS( signedBody ) ) )
```

### 4.3 Evidence Hash (Breach)

```
evidence_hash = lowercase_hex( SHA-256( UTF-8( JCS( evidence ) ) ) )
```

If no evidence is provided, `evidence_hash` is `null`.

### 4.4 Signed Body Construction (Breach)

```json
{
  "breach_description": "<string>",
  "breach_id":          "<uuid-v4>",
  "evidence_hash":      "<hex or null>",
  "reported_at":        "<ISO-8601 UTC>",
  "warranty_id":        "<string>"
}
```

### 4.5 Verification Recipe

**Warranty receipt:**

1. Extract signed body fields from `warranty` (exclude `warranty.signing`; exclude null/missing optional fields).
2. Assert `Ed25519Verify( issuerPublicKey, UTF-8( JCS( signedBody ) ), sigBytes ) == true`.
3. If `warranty.expires_at` is present and non-null, assert `expires_at > now_utc()`.
4. Assert `warranty.signing.key_id == base64url_no_pad( SHA-256( issuerPublicKey ) )`.

**Breach receipt:**

1. Extract signed body fields from `breach_record` (exclude `breach_record.signing`).
2. Assert `Ed25519Verify( issuerPublicKey, UTF-8( JCS( signedBody ) ), sigBytes ) == true`.

---

## 5. Endpoints (HTTP)

Base URL: `https://hivemorph.onrender.com`

### 5.1 Issue a Warranty

```
POST /v1/attest/warranty/issue
Content-Type: application/json
```

**Example request (with stake):**

```json
{
  "agent_did":  "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
  "action_id":  "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "claim":      "The attached dataset contains no GDPR-defined personal data.",
  "scope":      "dataset:reports/2026-Q1.csv@sha256:abc123",
  "expires_at": "2026-08-02T00:00:00.000Z",
  "stake": {
    "amount":   "500",
    "currency": "USD",
    "terms":    "Forfeited if PII is found within scope by independent auditor within 90 days."
  }
}
```

**Example response (HTTP 200):**

```json
{
  "warranty": {
    "warranty_id":  "1d2e3f4a-5b6c-7d8e-9f0a-1b2c3d4e5f6a",
    "agent_did":    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    "action_id":    "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "claim":        "The attached dataset contains no GDPR-defined personal data.",
    "scope":        "dataset:reports/2026-Q1.csv@sha256:abc123",
    "issued_at":    "2026-05-02T14:00:00.000Z",
    "expires_at":   "2026-08-02T00:00:00.000Z",
    "stake": {
      "amount":   "500",
      "currency": "USD",
      "terms":    "Forfeited if PII is found within scope by independent auditor within 90 days."
    },
    "breach_status":"none",
    "signing": {
      "algorithm": "EdDSA",
      "curve":     "Ed25519",
      "key_id":    "ZoRSOrFzpuqyLbCgJLRkpCRB2iSjT7tMmrNV9xWfBQA",
      "signature": "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdefghijklmnopqrstuvwxyz01"
    }
  },
  "_meta": {
    "layer":            "C",
    "production_grade": false,
    "spec_url":         "https://raw.githubusercontent.com/srotzin/hive-attestation-warranty/main/SPEC.md",
    "patent":           "USPTO 64/055,601",
    "claim":            "C18"
  }
}
```

### 5.2 Report a Breach

```
POST /v1/attest/warranty/breach
Content-Type: application/json
```

**Example request:**

```json
{
  "warranty_id":        "1d2e3f4a-5b6c-7d8e-9f0a-1b2c3d4e5f6a",
  "breach_description": "PII (email addresses) found in rows 45-48 of reports/2026-Q1.csv.",
  "evidence":           { "row_indices": [45, 46, 47, 48], "field": "contact_email" }
}
```

**Example response (HTTP 200):**

```json
{
  "breach_record": {
    "breach_id":          "9e8d7c6b-5a4f-3e2d-1c0b-a9b8c7d6e5f4",
    "warranty_id":        "1d2e3f4a-5b6c-7d8e-9f0a-1b2c3d4e5f6a",
    "breach_description": "PII (email addresses) found in rows 45-48 of reports/2026-Q1.csv.",
    "evidence_hash":      "7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a",
    "reported_at":        "2026-05-10T09:15:00.000Z",
    "signing": {
      "algorithm": "EdDSA",
      "curve":     "Ed25519",
      "key_id":    "ZoRSOrFzpuqyLbCgJLRkpCRB2iSjT7tMmrNV9xWfBQA",
      "signature": "XyZaBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFg"
    }
  },
  "_meta": {
    "layer":            "C",
    "production_grade": false,
    "spec_url":         "https://raw.githubusercontent.com/srotzin/hive-attestation-warranty/main/SPEC.md",
    "patent":           "USPTO 64/055,601",
    "claim":            "C18"
  }
}
```

### 5.3 Fetch a Warranty by ID

```
GET /v1/attest/warranty/{warranty_id}
```

Returns the warranty object with current `breach_status` and any associated
breach records as an array.

**Error responses:**

| HTTP Status | Condition |
|-------------|-----------|
| 400 | Missing required field |
| 404 | `warranty_id` not found (breach and GET endpoints) |
| 422 | `expires_at` is in the past at time of issuance |

---

## 6. Layer C Honesty Contract

Every response from this endpoint MUST carry:

- **HTTP header:** `X-Hive-Layer: C-Reference`
- **Body field `_meta.layer`:** `"C"`
- **Body field `_meta.production_grade`:** `false`
- **Body field `_meta.spec_url`:** `"https://raw.githubusercontent.com/srotzin/hive-attestation-warranty/main/SPEC.md"`
- **Body field `_meta.patent`:** `"USPTO 64/055,601"`
- **Body field `_meta.claim`:** `"C18"`

---

## 7. Receipts and Verifiability

Given only the warranty receipt and the issuer's 32-byte Ed25519 public key,
a third party MUST be able to:

1. **Verify signature integrity** per Section 4.5. Any tampering with a signed
   field invalidates the signature.
2. **Verify temporal validity:** check `expires_at` against the current UTC time
   (if present).
3. **Verify key binding** via `key_id`.
4. **Verify breach-record integrity** per Section 4.5 for each breach record.
5. **Verify evidence integrity:** if `evidence` is available, re-compute
   `JCS + SHA-256` and compare to `breach_record.evidence_hash`.

The `warranty_id` is suitable as a durable receipt identifier in contracts,
audit logs, and escalation workflows.

Stake enforcement — verifying that a declared stake was actually forfeited in
response to a confirmed breach — is out of scope for Layer C and requires
Layer B adjudication infrastructure.

---

## 8. Security Considerations

1. **In-process key storage.** The Ed25519 private key is held in process memory.
   A process compromise allows forged warranty and breach receipts.

2. **No key rotation.** A single key pair signs all warranties. If the signing
   key is compromised, all issued warranties become suspect.

3. **Breach status is server-side state.** `breach_status` is stored by the
   issuer. It is not reflected in the original warranty's signature (which was
   computed at issuance time). Relying parties MUST fetch the current warranty
   state from the server to check `breach_status`; the original receipt alone
   only proves issuance, not current standing.

4. **Stake is declaratory, not escrow.** The `stake` fields record a claim but
   do not lock funds. The warrantor could refuse to pay upon breach. A Layer B
   implementation MUST integrate with a payment rail or smart contract to make
   stakes enforceable.

5. **No transparency log.** Warranties and breach records are not published to
   an external auditable log. The issuer can silently suppress breach records.

6. **No DID resolution.** `agent_did` is accepted verbatim. Any syntactically
   valid DID is accepted as the warrantor identity.

7. **Claim text is unstructured.** The `claim` field is free-form English. There
   is no machine-checkable assertion language; disputes about whether a claim was
   breached require human or out-of-band adjudication.

8. **No revocation of warranties.** A warranty cannot be retracted once issued.
   The issuer can add breach records but cannot delete the warranty object.

---

## 9. References

- USPTO Provisional Application No. 64/055,601 — HiveAttest patent family
- RFC 8032 — Edwards-Curve Digital Signature Algorithm (EdDSA)
- RFC 8785 — JSON Canonicalization Scheme (JCS)
- RFC 2119 — Key words for use in RFCs to Indicate Requirement Levels
- FIPS 180-4 — Secure Hash Standard (SHA-256)

---

## Appendix A. Test Vectors

**Vector 1: Issue a minimal warranty (no stake, no expiry)**

```
POST https://hivemorph.onrender.com/v1/attest/warranty/issue
Content-Type: application/json

{
  "agent_did": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuias8siQmFe2BCM7",
  "action_id": "00000000-0000-0000-0000-000000000003",
  "claim":     "Test claim for vector A.",
  "scope":     "urn:test:vector:warranty:A"
}
```

Expected: HTTP 200, `warranty.breach_status == "none"`,
`warranty.expires_at == null`, `warranty.stake == null`.

**Vector 2: Issue with stake and expiry**

```json
{
  "agent_did":  "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuias8siQmFe2BCM7",
  "action_id":  "00000000-0000-0000-0000-000000000004",
  "claim":      "No toxicity detected in model output.",
  "scope":      "session:test-session-001",
  "expires_at": "2030-01-01T00:00:00.000Z",
  "stake": {
    "amount": "100", "currency": "USD",
    "terms": "Payable within 30 days of confirmed breach."
  }
}
```

Expected: HTTP 200, `warranty.stake.amount == "100"`.

**Vector 3: Record a breach for Vector 1**

```
POST https://hivemorph.onrender.com/v1/attest/warranty/breach
Content-Type: application/json

{
  "warranty_id":        "<warranty_id from Vector 1>",
  "breach_description": "Test breach for vector A.",
  "evidence":           { "note": "test" }
}
```

Expected: HTTP 200, `breach_record.warranty_id` matches Vector 1's `warranty_id`.
Subsequent `GET /v1/attest/warranty/<warranty_id>` returns `breach_status == "alleged"`.
