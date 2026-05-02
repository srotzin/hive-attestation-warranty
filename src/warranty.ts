/**
 * hive-attestation-warranty — Attestation-as-Warranty (HiveAttest Claim C18).
 *
 * An Attestation is a WARRANTY:
 *   - Issuer has stake at risk
 *   - Breach is auditable (evidence package)
 *   - Breach triggers slash/refund flow
 *   - Double-claim prevention (one breach claim per attestation)
 *
 * All signing is Ed25519 over JCS-canonicalized bodies.
 *
 * @license Apache-2.0
 * @copyright Copyright 2026 Stephen A. Rotzin
 */

import * as ed from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { sha512 } from "@noble/hashes/sha512";
import type {
  BreachClaimResult,
  BreachEvidence,
  VerifyAttestationResult,
  WarrantyAttestation,
  WarrantyStatus,
} from "./types.js";

ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

function b64uEncode(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function b64uDecode(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64.padEnd(b64.length + ((4 - (b64.length % 4)) % 4), "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function bytesToHex(b: Uint8Array): string {
  return Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
}

function sha256Hex(data: string): string {
  return bytesToHex(sha256(new TextEncoder().encode(data)));
}

// ---------------------------------------------------------------------------
// JCS canonicalize
// ---------------------------------------------------------------------------

function canonicalize(v: unknown): string {
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") return JSON.stringify(v)!;
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(",")}]`;
  if (typeof v === "object") {
    const obj = v as Record<string, unknown>;
    const keys = Object.keys(obj).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${keys.filter((k) => obj[k] !== undefined)
      .map((k) => `${JSON.stringify(k)}:${canonicalize(obj[k])}`).join(",")}}`;
  }
  throw new TypeError(`canonicalize: ${typeof v}`);
}

// ---------------------------------------------------------------------------
// UUID helper
// ---------------------------------------------------------------------------

function randomUUID(): string {
  const c = (globalThis as Record<string, unknown>).crypto as { randomUUID?: () => string } | undefined;
  if (c?.randomUUID) return c.randomUUID();
  const b = ed.utils.randomPrivateKey().slice(0, 16);
  b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80;
  const h = bytesToHex(b);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

// ---------------------------------------------------------------------------
// Signing helpers
// ---------------------------------------------------------------------------

function signingBody(a: WarrantyAttestation): Uint8Array {
  const body = {
    attestation_id: a.attestation_id,
    beneficiary_did: a.beneficiary_did,
    expires_at: a.expires_at,
    hive_warranty_version: a.hive_warranty_version,
    issued_at: a.issued_at,
    issuer_did: a.issuer_did,
    key_id: a.key_id,
    stake_amount: a.stake_amount,
    warranted_hash: a.warranted_hash,
    warranty_statement: a.warranty_statement,
    // signature intentionally omitted
  };
  return new TextEncoder().encode(canonicalize(body));
}

export function hashData(data: unknown): string {
  return sha256Hex(canonicalize(data));
}

// ---------------------------------------------------------------------------
// WarrantyIssuer
// ---------------------------------------------------------------------------

export class WarrantyIssuer {
  private readonly privKey: Uint8Array;
  private readonly pubKeyB64u: string;
  private readonly issuerDid: string;

  constructor(privKey: Uint8Array, issuerDid: string) {
    if (privKey.length !== 32) throw new Error("Expected 32-byte private key");
    this.privKey = privKey;
    this.pubKeyB64u = b64uEncode(ed.getPublicKey(privKey));
    this.issuerDid = issuerDid;
  }

  issue(opts: {
    beneficiaryDid: string;
    warrantyStatement: string;
    warrantedData: unknown;
    stakeAmount: number;
    ttlSeconds?: number;
    nowMs?: number;
  }): WarrantyAttestation {
    const nowMs = opts.nowMs ?? Date.now();
    const ttl = opts.ttlSeconds ?? 86_400; // default 24h
    const issuedAt = new Date(nowMs).toISOString();
    const expiresAt = new Date(nowMs + ttl * 1000).toISOString();
    const attestationId = randomUUID();
    const warrantedHash = hashData(opts.warrantedData);

    const partial: Omit<WarrantyAttestation, "signature"> = {
      attestation_id: attestationId,
      hive_warranty_version: "hive-warranty/1",
      issuer_did: this.issuerDid,
      beneficiary_did: opts.beneficiaryDid,
      warranty_statement: opts.warrantyStatement,
      warranted_hash: warrantedHash,
      issued_at: issuedAt,
      expires_at: expiresAt,
      stake_amount: opts.stakeAmount,
      key_id: this.pubKeyB64u,
    };

    const bodyBytes = signingBody(partial as WarrantyAttestation);
    const sig = ed.sign(bodyBytes, this.privKey);
    return { ...partial, signature: b64uEncode(sig) };
  }
}

// ---------------------------------------------------------------------------
// WarrantyVerifier
// ---------------------------------------------------------------------------

export class WarrantyVerifier {
  private readonly trustedPubKeyB64u: string | null;

  constructor(trustedPubKeyB64u: string | null = null) {
    this.trustedPubKeyB64u = trustedPubKeyB64u;
  }

  async verify(
    attestation: WarrantyAttestation,
    opts: { nowMs?: number; pubkeyB64u?: string } = {},
  ): Promise<VerifyAttestationResult> {
    const nowMs = opts.nowMs ?? Date.now();

    // Temporal
    const expiresMs = new Date(attestation.expires_at).getTime();
    if (nowMs > expiresMs) {
      return { valid: false, status: "expired", reason: "Attestation has expired" };
    }

    // Signature
    const pubKeyB64u = opts.pubkeyB64u ?? this.trustedPubKeyB64u ?? attestation.key_id;
    let pubBytes: Uint8Array;
    try {
      pubBytes = b64uDecode(pubKeyB64u);
      if (pubBytes.length !== 32) throw new Error(`expected 32 bytes, got ${pubBytes.length}`);
    } catch (e) {
      return { valid: false, status: null, reason: `Bad public key: ${e instanceof Error ? e.message : String(e)}` };
    }

    let sigBytes: Uint8Array;
    try {
      sigBytes = b64uDecode(attestation.signature);
      if (sigBytes.length !== 64) throw new Error(`expected 64 bytes, got ${sigBytes.length}`);
    } catch (e) {
      return { valid: false, status: null, reason: `Bad signature: ${e instanceof Error ? e.message : String(e)}` };
    }

    const bodyBytes = signingBody(attestation);
    let sigOk: boolean;
    try {
      sigOk = await ed.verifyAsync(sigBytes, bodyBytes, pubBytes);
    } catch {
      sigOk = false;
    }

    if (!sigOk) {
      return { valid: false, status: null, reason: "Signature invalid" };
    }

    const fingerprint = bytesToHex(sha256(bodyBytes));
    return { valid: true, status: "active", fingerprint };
  }
}

// ---------------------------------------------------------------------------
// WarrantyLedger — tracks issued warranties, breach claims, slash/refund
// ---------------------------------------------------------------------------

export class WarrantyLedger {
  private readonly attestations = new Map<string, WarrantyAttestation>();
  private readonly statuses = new Map<string, WarrantyStatus>();
  private readonly breachClaims = new Set<string>(); // attestation_ids already claimed
  private readonly slashLog: Array<{ attestationId: string; amount: number; claimant: string }> = [];

  register(attestation: WarrantyAttestation): void {
    this.attestations.set(attestation.attestation_id, attestation);
    this.statuses.set(attestation.attestation_id, "active");
  }

  getStatus(attestationId: string): WarrantyStatus | undefined {
    return this.statuses.get(attestationId);
  }

  /**
   * Submit breach evidence.
   *
   * Checks:
   * 1. Attestation exists and is active
   * 2. Claimant matches beneficiary_did
   * 3. No double-claim (each attestation can be breached once)
   * 4. Evidence hash differs from warranted hash (actual breach)
   * 5. Breach observed within validity window
   */
  claimBreach(evidence: BreachEvidence, _nowMs?: number): BreachClaimResult {
    const attestation = this.attestations.get(evidence.attestation_id);
    if (!attestation) {
      return { accepted: false, attestationId: evidence.attestation_id, reason: "Attestation not found" };
    }

    // Double-claim prevention (check before status so we get the specific error)
    if (this.breachClaims.has(evidence.attestation_id)) {
      return { accepted: false, attestationId: evidence.attestation_id, reason: "Breach already claimed for this attestation" };
    }

    const status = this.statuses.get(evidence.attestation_id)!;
    if (status !== "active") {
      return { accepted: false, attestationId: evidence.attestation_id, reason: `Attestation status is "${status}", not active` };
    }

    // Claimant must be beneficiary
    if (evidence.claimant_did !== attestation.beneficiary_did) {
      return { accepted: false, attestationId: evidence.attestation_id, reason: "Claimant is not the beneficiary" };
    }

    // Evidence must show actual_hash differs from warranted_hash
    if (evidence.actual_hash === attestation.warranted_hash) {
      return { accepted: false, attestationId: evidence.attestation_id, reason: "actual_hash matches warranted_hash — no breach detected" };
    }

    // Breach must be observed before expiry
    const observedMs = new Date(evidence.observed_at).getTime();
    const expiresMs = new Date(attestation.expires_at).getTime();
    if (observedMs > expiresMs) {
      return { accepted: false, attestationId: evidence.attestation_id, reason: "Breach observed after warranty expiry" };
    }

    // Accept breach
    this.breachClaims.add(evidence.attestation_id);
    this.statuses.set(evidence.attestation_id, "breached");
    const slashAmount = attestation.stake_amount; // full slash on breach
    this.slashLog.push({ attestationId: evidence.attestation_id, amount: slashAmount, claimant: evidence.claimant_did });

    return { accepted: true, attestationId: evidence.attestation_id, slashAmount };
  }

  /** Expire attestations past their valid_until. */
  expireStale(nowMs?: number): number {
    const t = nowMs ?? Date.now();
    let count = 0;
    for (const [id, attestation] of this.attestations.entries()) {
      if (this.statuses.get(id) === "active" && new Date(attestation.expires_at).getTime() < t) {
        this.statuses.set(id, "expired");
        count++;
      }
    }
    return count;
  }

  getSlashLog() {
    return this.slashLog.slice();
  }
}
