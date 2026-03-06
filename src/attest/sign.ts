import nacl from 'tweetnacl';
import { canonicalize, canonicalHash } from './canonicalize';
import { Attestation, AttestationSubject, Evidence } from './types';
import { LLMReview } from '../schema';
import { Policy } from '../schema';

export interface SigningInput {
  subject: AttestationSubject;
  evidence: Evidence;
  review: LLMReview;
  policy: Policy;
}

export interface SigningResult {
  attestation: Attestation;
  publicKeyB64: string;
}

export function signAttestation(input: SigningInput, privateKeySeedB64: string): SigningResult {
  const seed = Buffer.from(privateKeySeedB64, 'base64');
  if (seed.length !== 32) {
    throw new Error(`Ed25519 seed must be 32 bytes, got ${seed.length}`);
  }

  const keyPair = nacl.sign.keyPair.fromSeed(new Uint8Array(seed));

  const policyDigest = canonicalHash(input.policy);
  const evidenceDigest = canonicalHash(input.evidence);
  const reviewDigest = canonicalHash(input.review);

  const payload = canonicalize({
    schemaVersion: '1.0.0',
    subject: input.subject,
    policyDigest,
    evidenceDigest,
    reviewDigest,
  });

  const payloadBytes = new TextEncoder().encode(payload);
  const signature = nacl.sign.detached(payloadBytes, keyPair.secretKey);

  const publicKeyB64 = Buffer.from(keyPair.publicKey).toString('base64');
  const signatureB64 = Buffer.from(signature).toString('base64');

  const attestation: Attestation = {
    schemaVersion: '1.0.0',
    subject: input.subject,
    policyDigest,
    evidenceDigest,
    reviewDigest,
    signature: signatureB64,
    publicKey: publicKeyB64,
    timestamp: new Date().toISOString(),
  };

  return { attestation, publicKeyB64 };
}
