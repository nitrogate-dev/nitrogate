export interface AttestationSubject {
  repo: string;
  pr: number;
  commit: string;
}

export interface Attestation {
  schemaVersion: string;
  subject: AttestationSubject;
  policyDigest: string;
  evidenceDigest: string;
  reviewDigest: string;
  signature: string;
  publicKey: string;
  timestamp: string;
}

export interface Evidence {
  repo: string;
  pr: number;
  baseSha: string;
  headSha: string;
  changedFiles: string[];
  diffSha256: string;
  truncated: boolean;
  originalDiffBytes: number;
  policyDigestSha256: string;
  llmProvider: string;
  llmModel: string;
  llmValid: boolean;
  policyViolations: number;
  mode: string;
  timestamp: string;
}
