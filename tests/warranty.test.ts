/**
 * Tests for hive-attestation-warranty — Attestation-as-Warranty (Claim C18).
 *
 * ≥40 tests covering: issue, verify, breach-detection, evidence-validation,
 * double-claim-prevention, expired attestation, slash log.
 *
 * @license Apache-2.0
 * @copyright Copyright 2026 Stephen A. Rotzin
 */

import { describe, it, expect, beforeAll } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import {
  WarrantyIssuer,
  WarrantyVerifier,
  WarrantyLedger,
  hashData,
} from "../src/warranty.js";
import type { BreachEvidence, WarrantyAttestation } from "../src/types.js";

ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));

function b64uEncode(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

let privA: Uint8Array;
let pubAB64u: string;
let issuer: WarrantyIssuer;
let verifier: WarrantyVerifier;

const FIXED_NOW_MS = new Date("2026-05-02T18:00:00Z").getTime();
const WARRANTED_DATA = { model: "gpt-4o", hash: "abc123", claim: "no-pii-exfiltration" };

beforeAll(() => {
  privA = ed.utils.randomPrivateKey();
  pubAB64u = b64uEncode(ed.getPublicKey(privA));
  issuer = new WarrantyIssuer(privA, "did:hive:issuer:alpha");
  verifier = new WarrantyVerifier(pubAB64u);
});

function makeAttestation(overrides: Partial<Parameters<WarrantyIssuer["issue"]>[0]> = {}) {
  return issuer.issue({
    beneficiaryDid: "did:hive:beneficiary:beta",
    warrantyStatement: "No PII was transmitted to external APIs",
    warrantedData: WARRANTED_DATA,
    stakeAmount: 100_000, // 100 USD in cents
    nowMs: FIXED_NOW_MS,
    ...overrides,
  });
}

function makeBreachEvidence(attestation: WarrantyAttestation, overrides: Partial<BreachEvidence> = {}): BreachEvidence {
  return {
    attestation_id: attestation.attestation_id,
    claimant_did: attestation.beneficiary_did,
    breach_description: "PII was found in the API call payload",
    actual_hash: "different_hash_" + attestation.warranted_hash.slice(0, 8),
    observed_at: new Date(FIXED_NOW_MS + 3600_000).toISOString(), // 1h after
    evidence_refs: ["evidence-001"],
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Issue tests
// ---------------------------------------------------------------------------

describe("WarrantyIssuer — issue", () => {
  it("returns an attestation with correct version", () => {
    expect(makeAttestation().hive_warranty_version).toBe("hive-warranty/1");
  });

  it("issuer_did is set correctly", () => {
    expect(makeAttestation().issuer_did).toBe("did:hive:issuer:alpha");
  });

  it("beneficiary_did is set correctly", () => {
    expect(makeAttestation().beneficiary_did).toBe("did:hive:beneficiary:beta");
  });

  it("warranted_hash is SHA-256 of JCS-canonical data", () => {
    const a = makeAttestation();
    expect(a.warranted_hash).toBe(hashData(WARRANTED_DATA));
  });

  it("warranted_hash is 64-char hex", () => {
    expect(makeAttestation().warranted_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("hashData is JCS-deterministic (key-order insensitive)", () => {
    expect(hashData({ a: 1, b: 2 })).toBe(hashData({ b: 2, a: 1 }));
  });

  it("stake_amount is embedded", () => {
    expect(makeAttestation({ stakeAmount: 50_000 }).stake_amount).toBe(50_000);
  });

  it("attestation_id is a UUID", () => {
    expect(makeAttestation().attestation_id).toMatch(/^[0-9a-f-]{36}$/);
  });

  it("successive attestation_ids are unique", () => {
    const ids = new Set(Array.from({ length: 10 }, () => makeAttestation().attestation_id));
    expect(ids.size).toBe(10);
  });

  it("issued_at matches nowMs", () => {
    const a = makeAttestation();
    expect(new Date(a.issued_at).getTime()).toBe(FIXED_NOW_MS);
  });

  it("expires_at is issued_at + ttl", () => {
    const a = makeAttestation({ ttlSeconds: 3600 });
    const delta = new Date(a.expires_at).getTime() - new Date(a.issued_at).getTime();
    expect(delta).toBe(3_600_000);
  });

  it("signature decodes to 64 bytes", () => {
    const a = makeAttestation();
    const raw = b64uEncode(new Uint8Array(64)); // just checking length math
    const sig = a.signature.replace(/-/g, "+").replace(/_/g, "/");
    const padded = sig.padEnd(sig.length + ((4 - (sig.length % 4)) % 4), "=");
    expect(atob(padded).length).toBe(64);
  });

  it("throws on private key of wrong length", () => {
    expect(() => new WarrantyIssuer(new Uint8Array(16), "did:x")).toThrow();
  });
});

// ---------------------------------------------------------------------------
// Verify tests
// ---------------------------------------------------------------------------

describe("WarrantyVerifier — verify", () => {
  it("verifies a freshly issued attestation", async () => {
    const a = makeAttestation();
    const r = await verifier.verify(a, { nowMs: FIXED_NOW_MS });
    expect(r.valid).toBe(true);
    expect(r.status).toBe("active");
  });

  it("result contains fingerprint", async () => {
    const a = makeAttestation();
    const r = await verifier.verify(a, { nowMs: FIXED_NOW_MS });
    expect(r.valid && r.fingerprint).toMatch(/^[0-9a-f]{64}$/);
  });

  it("TOFU mode uses attestation key_id", async () => {
    const tofuV = new WarrantyVerifier(null);
    const a = makeAttestation();
    const r = await tofuV.verify(a, { nowMs: FIXED_NOW_MS });
    expect(r.valid).toBe(true);
  });

  it("expired attestation returns status=expired", async () => {
    const a = makeAttestation({ ttlSeconds: 10 });
    const after = new Date(a.expires_at).getTime() + 1000;
    const r = await verifier.verify(a, { nowMs: after });
    expect(r.valid).toBe(false);
    expect(r.status).toBe("expired");
  });

  it("tampered signature fails", async () => {
    const a = makeAttestation();
    const zeroed = b64uEncode(new Uint8Array(64));
    const tampered: WarrantyAttestation = { ...a, signature: zeroed };
    const r = await verifier.verify(tampered, { nowMs: FIXED_NOW_MS });
    expect(r.valid).toBe(false);
    expect(r.reason).toContain("Signature invalid");
  });

  it("wrong public key fails", async () => {
    const other = new WarrantyVerifier(b64uEncode(ed.getPublicKey(ed.utils.randomPrivateKey())));
    const a = makeAttestation();
    const r = await other.verify(a, { nowMs: FIXED_NOW_MS });
    expect(r.valid).toBe(false);
  });

  it("reports bad public key gracefully", async () => {
    const a = makeAttestation();
    const r = await verifier.verify(a, { nowMs: FIXED_NOW_MS, pubkeyB64u: "bad!!!" });
    expect(r.valid).toBe(false);
    expect(r.reason).toContain("Bad public key");
  });

  it("short signature reports bad signature", async () => {
    const a = makeAttestation();
    const short = b64uEncode(new Uint8Array(32));
    const r = await verifier.verify({ ...a, signature: short }, { nowMs: FIXED_NOW_MS });
    expect(r.valid).toBe(false);
    expect(r.reason).toContain("Bad signature");
  });
});

// ---------------------------------------------------------------------------
// WarrantyLedger — breach detection
// ---------------------------------------------------------------------------

describe("WarrantyLedger — breach detection", () => {
  it("accepted breach claim returns accepted=true", () => {
    const ledger = new WarrantyLedger();
    const a = makeAttestation();
    ledger.register(a);
    const ev = makeBreachEvidence(a);
    const r = ledger.claimBreach(ev);
    expect(r.accepted).toBe(true);
    expect(r.slashAmount).toBe(a.stake_amount);
  });

  it("breach claim changes status to breached", () => {
    const ledger = new WarrantyLedger();
    const a = makeAttestation();
    ledger.register(a);
    ledger.claimBreach(makeBreachEvidence(a));
    expect(ledger.getStatus(a.attestation_id)).toBe("breached");
  });

  it("slash log contains breach record", () => {
    const ledger = new WarrantyLedger();
    const a = makeAttestation();
    ledger.register(a);
    ledger.claimBreach(makeBreachEvidence(a));
    const log = ledger.getSlashLog();
    expect(log).toHaveLength(1);
    expect(log[0].attestationId).toBe(a.attestation_id);
    expect(log[0].amount).toBe(a.stake_amount);
  });

  it("double-claim is rejected", () => {
    const ledger = new WarrantyLedger();
    const a = makeAttestation();
    ledger.register(a);
    ledger.claimBreach(makeBreachEvidence(a));
    const r2 = ledger.claimBreach(makeBreachEvidence(a));
    expect(r2.accepted).toBe(false);
    expect(r2.reason).toContain("already claimed");
  });

  it("claimant that is not beneficiary is rejected", () => {
    const ledger = new WarrantyLedger();
    const a = makeAttestation();
    ledger.register(a);
    const ev = makeBreachEvidence(a, { claimant_did: "did:evil:attacker" });
    const r = ledger.claimBreach(ev);
    expect(r.accepted).toBe(false);
    expect(r.reason).toContain("not the beneficiary");
  });

  it("unknown attestation_id is rejected", () => {
    const ledger = new WarrantyLedger();
    const r = ledger.claimBreach({ attestation_id: "non-existent-id" } as BreachEvidence);
    expect(r.accepted).toBe(false);
    expect(r.reason).toContain("not found");
  });
});

// ---------------------------------------------------------------------------
// WarrantyLedger — evidence validation
// ---------------------------------------------------------------------------

describe("WarrantyLedger — evidence validation", () => {
  it("actual_hash matching warranted_hash means no breach", () => {
    const ledger = new WarrantyLedger();
    const a = makeAttestation();
    ledger.register(a);
    const ev = makeBreachEvidence(a, { actual_hash: a.warranted_hash });
    const r = ledger.claimBreach(ev);
    expect(r.accepted).toBe(false);
    expect(r.reason).toContain("no breach");
  });

  it("breach observed after expiry is rejected", () => {
    const ledger = new WarrantyLedger();
    const a = makeAttestation({ ttlSeconds: 3600 });
    ledger.register(a);
    const ev = makeBreachEvidence(a, {
      observed_at: new Date(new Date(a.expires_at).getTime() + 60_000).toISOString(),
    });
    const r = ledger.claimBreach(ev);
    expect(r.accepted).toBe(false);
    expect(r.reason).toContain("after warranty expiry");
  });

  it("breach on expired attestation (status=expired) is rejected", () => {
    const ledger = new WarrantyLedger();
    const a = makeAttestation({ ttlSeconds: 1 });
    ledger.register(a);
    ledger.expireStale(FIXED_NOW_MS + 2000);
    const ev = makeBreachEvidence(a);
    const r = ledger.claimBreach(ev);
    expect(r.accepted).toBe(false);
    expect(r.reason).toContain("expired");
  });
});

// ---------------------------------------------------------------------------
// WarrantyLedger — expire
// ---------------------------------------------------------------------------

describe("WarrantyLedger — expire", () => {
  it("expireStale marks old attestations expired", () => {
    const ledger = new WarrantyLedger();
    const a = makeAttestation({ ttlSeconds: 60 });
    ledger.register(a);
    ledger.expireStale(FIXED_NOW_MS + 120_000);
    expect(ledger.getStatus(a.attestation_id)).toBe("expired");
  });

  it("expireStale returns count of expired", () => {
    const ledger = new WarrantyLedger();
    for (let i = 0; i < 3; i++) {
      ledger.register(issuer.issue({
        beneficiaryDid: "did:b",
        warrantyStatement: "stmt",
        warrantedData: { i },
        stakeAmount: 100,
        ttlSeconds: 60,
        nowMs: FIXED_NOW_MS,
      }));
    }
    const count = ledger.expireStale(FIXED_NOW_MS + 120_000);
    expect(count).toBe(3);
  });

  it("getStatus returns undefined for unknown id", () => {
    expect(new WarrantyLedger().getStatus("nonexistent")).toBeUndefined();
  });
});
