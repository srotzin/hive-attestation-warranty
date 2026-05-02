# @hivecivilization/hive-attestation-warranty

> **Layer C — Reference Primitive.** This is a public reference implementation. The wire format (see `SPEC.md` where present) is normative; this code is illustrative. Production-grade implementations of these specs run on the closed-source Hive Civilization platform with HSM-backed key custody, immutable transparency-log audit, multi-region sovereign federation, and SOC 2 / ISO 27001 / FedRAMP-track controls. Fork freely; conform to the spec.


<div align="center">
<img src="https://img.shields.io/badge/license-Apache%202.0-FFB800?style=flat-square" />
<img src="https://img.shields.io/badge/patent%20pending-USPTO%2064%2F055%2C601-FFB800?style=flat-square" />
<img src="https://img.shields.io/badge/tests-43%20passing-FFB800?style=flat-square" />
</div>

**Attestation-as-Warranty: signed attestations with issuer stake, breach detection, and auditable slash/refund flow.**

The act of signing and submitting an attestation constitutes a **warranty** — the issuer's stake is at risk if the declaration proves false. Breach evidence is auditable and tamper-evident. Double-claim prevention ensures each attestation can be disputed at most once.

---

## Claim Reference

**USPTO 64/055,601 — HiveAttest Claim C18**

> *An Attestation-as-Warranty method for autonomous agent systems: the submission of a signed Attestation Manifest constitutes a legally-operative warranty; the issuing agent's stake is committed at issuance; breach is established by submitting cryptographic evidence that the actual state differs from the warranted state; the ledger records the breach, enforces single-claim semantics, and computes the slash amount.*

---

## Quick Start

```typescript
import { WarrantyIssuer, WarrantyVerifier, WarrantyLedger, hashData } from "@hivecivilization/hive-attestation-warranty";
import * as ed from "@noble/ed25519";

const privKey = ed.utils.randomPrivateKey();
const issuer = new WarrantyIssuer(privKey, "did:hive:agent:alpha");

// Issue a warranty
const attestation = issuer.issue({
  beneficiaryDid: "did:hive:agent:beta",
  warrantyStatement: "No PII was transmitted to external APIs",
  warrantedData: { payload_hash: "abc123" },
  stakeAmount: 100_000, // 100 USD in cents
  ttlSeconds: 3600,
});

// Register in ledger
const ledger = new WarrantyLedger();
ledger.register(attestation);

// Claim breach
const result = ledger.claimBreach({
  attestation_id: attestation.attestation_id,
  claimant_did: attestation.beneficiary_did,
  breach_description: "PII found in transmitted payload",
  actual_hash: hashData({ payload_hash: "DIFFERENT" }),
  observed_at: new Date().toISOString(),
  evidence_refs: ["audit-log-ref-001"],
});

console.log(result.accepted); // true
console.log(result.slashAmount); // 100000
```

---

## NOTICE

Reference implementation — USPTO 64/055,601, HiveAttest Claim C18.  
Inventor: Stephen A. Rotzin. Apache License 2.0.
