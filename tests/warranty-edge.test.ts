/**
 * Edge-case tests to hit uncovered branches in warranty.ts.
 *
 * @license Apache-2.0
 * @copyright Copyright 2026 Stephen A. Rotzin
 */

import { describe, it, expect, beforeAll } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { WarrantyIssuer, WarrantyVerifier, hashData } from "../src/warranty.js";

ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));

function b64uEncode(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

let privA: Uint8Array;
let pubAB64u: string;
let issuer: WarrantyIssuer;
let verifier: WarrantyVerifier;

beforeAll(() => {
  privA = ed.utils.randomPrivateKey();
  pubAB64u = b64uEncode(ed.getPublicKey(privA));
  issuer = new WarrantyIssuer(privA, "did:hive:issuer:edge");
  verifier = new WarrantyVerifier(pubAB64u);
});

const FIXED_NOW_MS = new Date("2026-05-02T18:00:00Z").getTime();

function makeAttestation() {
  return issuer.issue({
    beneficiaryDid: "did:hive:bene:edge",
    warrantyStatement: "Edge case test",
    warrantedData: { edge: true },
    stakeAmount: 1000,
    nowMs: FIXED_NOW_MS,
  });
}

describe("warranty — additional branch coverage", () => {
  it("hashData handles null", () => {
    expect(hashData(null)).toMatch(/^[0-9a-f]{64}$/);
  });

  it("hashData handles arrays", () => {
    expect(hashData([1, 2, 3])).toMatch(/^[0-9a-f]{64}$/);
  });

  it("hashData handles strings", () => {
    expect(hashData("hello")).toMatch(/^[0-9a-f]{64}$/);
  });

  it("hashData handles numbers", () => {
    expect(hashData(42)).toMatch(/^[0-9a-f]{64}$/);
  });

  it("hashData handles booleans", () => {
    expect(hashData(true)).toMatch(/^[0-9a-f]{64}$/);
    expect(hashData(false)).toMatch(/^[0-9a-f]{64}$/);
  });

  it("two different objects produce different hashes", () => {
    expect(hashData({ a: 1 })).not.toBe(hashData({ a: 2 }));
  });

  it("verifyAsync called — short pubkey path returns bad public key", async () => {
    const a = makeAttestation();
    const shortKey = b64uEncode(new Uint8Array(16));
    const r = await verifier.verify(a, { nowMs: FIXED_NOW_MS, pubkeyB64u: shortKey });
    expect(r.valid).toBe(false);
    expect(r.reason).toContain("Bad public key");
  });

  it("mutated warranty_statement fails signature check", async () => {
    const a = makeAttestation();
    const tampered = { ...a, warranty_statement: "MUTATED" };
    const r = await verifier.verify(tampered, { nowMs: FIXED_NOW_MS });
    expect(r.valid).toBe(false);
    expect(r.reason).toContain("Signature invalid");
  });

  it("mutated stake_amount fails signature check", async () => {
    const a = makeAttestation();
    const tampered = { ...a, stake_amount: 0 };
    const r = await verifier.verify(tampered, { nowMs: FIXED_NOW_MS });
    expect(r.valid).toBe(false);
  });

  it("mutated warranted_hash fails signature check", async () => {
    const a = makeAttestation();
    const tampered = { ...a, warranted_hash: "a".repeat(64) };
    const r = await verifier.verify(tampered, { nowMs: FIXED_NOW_MS });
    expect(r.valid).toBe(false);
  });
});
