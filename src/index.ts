/**
 * @hivecivilization/hive-attestation-warranty
 * Reference implementation of HiveAttest Claim C18, USPTO 64/055,601.
 *
 * @license Apache-2.0
 * @copyright Copyright 2026 Stephen A. Rotzin
 */

export { WarrantyIssuer, WarrantyVerifier, WarrantyLedger, hashData } from "./warranty.js";
export type {
  WarrantyAttestation,
  BreachEvidence,
  BreachClaimResult,
  VerifyAttestationResult,
  WarrantyStatus,
} from "./types.js";
