import nacl from 'tweetnacl';
import { canonicalize, canonicalHash } from '../src/attest/canonicalize';
import { signAttestation } from '../src/attest/sign';
import { verifyAttestation } from '../src/attest/verify';
import { Evidence, Attestation } from '../src/attest/types';
import { LLMReview, Policy } from '../src/schema';

function makeTestSeed(): string {
  const seed = nacl.randomBytes(32);
  return Buffer.from(seed).toString('base64');
}

const TEST_POLICY: Policy = {
  allowedFileGlobs: ['**/*'],
  deniedFileGlobs: [],
  maxChangedFiles: 100,
  maxDiffBytes: 500_000,
  llm: { provider: 'mock', model: 'gpt-4o' },
  mode: 'advisory',
};

const TEST_REVIEW: LLMReview = {
  summary: 'Test review',
  blocking: [],
  nonBlocking: [],
  testPlan: [{ type: 'unit', what: 'test core logic' }],
};

const TEST_EVIDENCE: Evidence = {
  repo: 'owner/repo',
  pr: 1,
  baseSha: 'aaa',
  headSha: 'bbb',
  changedFiles: ['src/main.ts'],
  diffSha256: 'abc123',
  truncated: false,
  originalDiffBytes: 100,
  policyDigestSha256: 'def456',
  llmProvider: 'mock',
  llmModel: 'gpt-4o',
  llmValid: true,
  policyViolations: 0,
  mode: 'advisory',
  timestamp: '2025-01-01T00:00:00.000Z',
};

describe('canonicalize', () => {
  it('produces stable output regardless of key insertion order', () => {
    const a = { z: 1, a: 2, m: 3 };
    const b = { a: 2, m: 3, z: 1 };
    expect(canonicalize(a)).toBe(canonicalize(b));
  });

  it('handles nested objects', () => {
    const obj = { b: { d: 1, c: 2 }, a: 3 };
    const result = canonicalize(obj);
    expect(result).toBe('{"a":3,"b":{"c":2,"d":1}}');
  });

  it('handles arrays preserving order', () => {
    const obj = { items: [3, 1, 2] };
    expect(canonicalize(obj)).toBe('{"items":[3,1,2]}');
  });

  it('produces consistent hash for same content', () => {
    const h1 = canonicalHash({ z: 1, a: 2 });
    const h2 = canonicalHash({ a: 2, z: 1 });
    expect(h1).toBe(h2);
  });

  it('produces different hash for different content', () => {
    const h1 = canonicalHash({ a: 1 });
    const h2 = canonicalHash({ a: 2 });
    expect(h1).not.toBe(h2);
  });
});

describe('sign + verify', () => {
  it('round-trips: sign then verify succeeds', () => {
    const seed = makeTestSeed();
    const { attestation } = signAttestation({
      subject: { repo: 'owner/repo', pr: 1, commit: 'abc' },
      evidence: TEST_EVIDENCE,
      review: TEST_REVIEW,
      policy: TEST_POLICY,
    }, seed);

    const result = verifyAttestation(attestation);
    expect(result.valid).toBe(true);
    expect(result.error).toBeUndefined();
  });

  it('fails verification when evidence digest is tampered', () => {
    const seed = makeTestSeed();
    const { attestation } = signAttestation({
      subject: { repo: 'owner/repo', pr: 1, commit: 'abc' },
      evidence: TEST_EVIDENCE,
      review: TEST_REVIEW,
      policy: TEST_POLICY,
    }, seed);

    const tampered: Attestation = { ...attestation, evidenceDigest: 'tampered_digest_value' };
    const result = verifyAttestation(tampered);
    expect(result.valid).toBe(false);
  });

  it('fails verification when signature is tampered', () => {
    const seed = makeTestSeed();
    const { attestation } = signAttestation({
      subject: { repo: 'owner/repo', pr: 1, commit: 'abc' },
      evidence: TEST_EVIDENCE,
      review: TEST_REVIEW,
      policy: TEST_POLICY,
    }, seed);

    const badSig = Buffer.from(nacl.randomBytes(64)).toString('base64');
    const tampered: Attestation = { ...attestation, signature: badSig };
    const result = verifyAttestation(tampered);
    expect(result.valid).toBe(false);
  });

  it('fails verification when review digest is tampered', () => {
    const seed = makeTestSeed();
    const { attestation } = signAttestation({
      subject: { repo: 'owner/repo', pr: 1, commit: 'abc' },
      evidence: TEST_EVIDENCE,
      review: TEST_REVIEW,
      policy: TEST_POLICY,
    }, seed);

    const tampered: Attestation = { ...attestation, reviewDigest: 'wrong' };
    const result = verifyAttestation(tampered);
    expect(result.valid).toBe(false);
  });

  it('rejects invalid seed length', () => {
    expect(() => signAttestation({
      subject: { repo: 'owner/repo', pr: 1, commit: 'abc' },
      evidence: TEST_EVIDENCE,
      review: TEST_REVIEW,
      policy: TEST_POLICY,
    }, Buffer.from('tooshort').toString('base64'))).toThrow('32 bytes');
  });

  it('includes all expected fields in attestation', () => {
    const seed = makeTestSeed();
    const { attestation } = signAttestation({
      subject: { repo: 'owner/repo', pr: 1, commit: 'abc' },
      evidence: TEST_EVIDENCE,
      review: TEST_REVIEW,
      policy: TEST_POLICY,
    }, seed);

    expect(attestation.schemaVersion).toBe('1.0.0');
    expect(attestation.subject.repo).toBe('owner/repo');
    expect(attestation.policyDigest).toBeTruthy();
    expect(attestation.evidenceDigest).toBeTruthy();
    expect(attestation.reviewDigest).toBeTruthy();
    expect(attestation.signature).toBeTruthy();
    expect(attestation.publicKey).toBeTruthy();
    expect(attestation.timestamp).toBeTruthy();
  });
});
