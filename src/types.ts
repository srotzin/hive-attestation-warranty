/**
 * Types for hive-attestation-warranty — Attestation-as-Warranty (HiveAttest C18).
 *
 * @license Apache-2.0
 * @copyright Copyright 2026 Stephen A. Rotzin
 */

export type WarrantyStatus = "active" | "expired" | "breached" | "claimed";

/** A signed warranty attestation issued by an agent. */
export interface WarrantyAttestation {
  /** Unique attestation ID (UUID). */
  attestation_id: string;
  /** Protocol version. */
  hive_warranty_version: "hive-warranty/1";
  /** DID of the issuing agent (warrantor). */
  issuer_did: string;
  /** DID of the beneficiary (who may claim breach). */
  beneficiary_did: string;
  /** Human-readable description of what is being warranted. */
  warranty_statement: string;
  /** SHA-256 hex of JCS-canonical warranted data/artifact. */
  warranted_hash: string;
  /** ISO-8601 UTC issuance time. */
  issued_at: string;
  /** ISO-8601 UTC expiry — warranty void after this time. */
  expires_at: string;
  /** Stake amount (arbitrary unit, e.g. USD cents or token units). */
  stake_amount: number;
  /** Ed25519 signature over JCS body (excluding this field). */
  signature: string;
  /** Base64url raw 32-byte public key of the issuer. */
  key_id: string;
}

/** Evidence package submitted to claim a warranty breach. */
export interface BreachEvidence {
  /** ID of the attestation being disputed. */
  attestation_id: string;
  /** DID of the claimant (must match beneficiary_did). */
  claimant_did: string;
  /** Description of the breach. */
  breach_description: string;
  /** SHA-256 hex hash of the actual data that breached the warranty. */
  actual_hash: string;
  /** ISO-8601 UTC timestamp when breach was observed. */
  observed_at: string;
  /** Supporting evidence references (hashes, URLs, etc.). */
  evidence_refs: string[];
}

/** Result of a breach claim. */
export interface BreachClaimResult {
  accepted: boolean;
  attestationId: string;
  reason?: string;
  /** Slash amount (portion of stake forfeited). */
  slashAmount?: number;
}

/** Result of verifying an attestation. */
export interface VerifyAttestationResult {
  valid: boolean;
  status: WarrantyStatus | null;
  reason?: string;
  fingerprint?: string;
}
