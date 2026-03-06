import nacl from 'tweetnacl';
import { canonicalize } from './canonicalize';
import { Attestation } from './types';

export interface VerifyResult {
  valid: boolean;
  error?: string;
}

export function verifyAttestation(attestation: Attestation): VerifyResult {
  try {
    const publicKey = new Uint8Array(Buffer.from(attestation.publicKey, 'base64'));
    const signature = new Uint8Array(Buffer.from(attestation.signature, 'base64'));

    if (publicKey.length !== 32) {
      return { valid: false, error: `Invalid public key length: ${publicKey.length}` };
    }

    const payload = canonicalize({
      schemaVersion: attestation.schemaVersion,
      subject: attestation.subject,
      policyDigest: attestation.policyDigest,
      evidenceDigest: attestation.evidenceDigest,
      reviewDigest: attestation.reviewDigest,
    });

    const payloadBytes = new TextEncoder().encode(payload);
    const isValid = nacl.sign.detached.verify(payloadBytes, signature, publicKey);

    if (!isValid) {
      return { valid: false, error: 'Signature verification failed' };
    }

    return { valid: true };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return { valid: false, error: `Verification error: ${message}` };
  }
}
