import * as core from '@actions/core';
import * as path from 'path';
import { ActionsGitHubClient, GitHubClient, PRContext } from './github';
import { loadPolicy, evaluatePolicy, PolicyViolation } from './policy';
import { processDiff, hashContent } from './diff';
import { createProvider, runLLMReview, LLMProvider } from './llm';
import { signAttestation } from './attest/sign';
import { verifyAttestation } from './attest/verify';
import { Evidence } from './attest/types';
import { LLMReview, Policy } from './schema';
import { writeArtifacts, buildPRComment } from './output';

export interface RunDeps {
  ghClient: GitHubClient;
  repoRoot: string;
  signingKeyB64: string | undefined;
  openaiKey: string | undefined;
  anthropicKey: string | undefined;
  policyPath: string;
  outputDir: string;
}

export async function run(deps: RunDeps): Promise<void> {
  const ctx = deps.ghClient.getPRContext();
  core.info(`Processing PR #${ctx.prNumber} on ${ctx.repoFullName}`);

  const { policy, fromFile } = loadPolicy(deps.repoRoot, deps.policyPath);
  core.info(`Policy loaded (from file: ${fromFile}), mode: ${policy.mode}`);

  const changedFiles = await deps.ghClient.getChangedFiles(ctx);
  core.info(`Changed files: ${changedFiles.length}`);

  const violations = evaluatePolicy(policy, changedFiles);
  if (violations.length > 0) {
    core.warning(`Policy violations: ${violations.length}`);
    for (const v of violations) {
      core.warning(`  [${v.type}] ${v.message}`);
    }
  }

  const rawDiff = await deps.ghClient.getDiff(ctx);
  const diffResult = processDiff(rawDiff, policy.maxDiffBytes);
  core.info(`Diff: ${diffResult.originalBytes} bytes, truncated: ${diffResult.truncated}`);

  const provider = createProvider(policy, {
    openaiKey: deps.openaiKey,
    anthropicKey: deps.anthropicKey,
  });
  const llmResult = await runLLMReview(provider, {
    diff: diffResult.diff,
    changedFiles,
    repoFullName: ctx.repoFullName,
    prNumber: ctx.prNumber,
  }, policy);
  core.info(`LLM review valid: ${llmResult.valid}`);

  const policyDigest = hashContent(JSON.stringify(policy));
  const evidence: Evidence = {
    repo: ctx.repoFullName,
    pr: ctx.prNumber,
    baseSha: ctx.baseSha,
    headSha: ctx.headSha,
    changedFiles,
    diffSha256: diffResult.sha256,
    truncated: diffResult.truncated,
    originalDiffBytes: diffResult.originalBytes,
    policyDigestSha256: policyDigest,
    llmProvider: llmResult.provider,
    llmModel: llmResult.model,
    llmValid: llmResult.valid,
    policyViolations: violations.length,
    mode: policy.mode,
    timestamp: new Date().toISOString(),
  };

  let attestationResult: 'PASS' | 'FAIL' | 'SKIPPED' = 'SKIPPED';
  let attestation = null;

  if (deps.signingKeyB64) {
    try {
      const sigResult = signAttestation({
        subject: { repo: ctx.repoFullName, pr: ctx.prNumber, commit: ctx.headSha },
        evidence,
        review: llmResult.review,
        policy,
      }, deps.signingKeyB64);

      attestation = sigResult.attestation;

      const verResult = verifyAttestation(attestation);
      attestationResult = verResult.valid ? 'PASS' : 'FAIL';
      if (!verResult.valid) {
        core.error(`Attestation verification failed: ${verResult.error}`);
      } else {
        core.info('Attestation signature verified: PASS');
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      core.error(`Signing/verification error: ${msg}`);
      attestationResult = 'FAIL';
    }
  } else {
    core.warning('No signing key provided — attestation skipped. For forks this is expected.');
  }

  const artifacts = writeArtifacts(deps.outputDir, llmResult.review, evidence, attestation);
  core.info(`Artifacts written to ${deps.outputDir}`);

  const comment = buildPRComment(llmResult.review, violations, attestationResult, llmResult.valid, policy.mode);
  try {
    await deps.ghClient.postComment(ctx, comment);
    core.info('PR comment posted');
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    core.warning(`Failed to post PR comment (may lack permissions): ${msg}`);
  }

  core.setOutput('attestation-result', attestationResult);
  core.setOutput('review-summary', llmResult.review.summary);
  core.setOutput('blocking-count', String(llmResult.review.blocking.length));
  core.setOutput('policy-violations', String(violations.length));

  if (policy.mode === 'gate' && violations.length > 0) {
    core.setFailed(`AflockGate: ${violations.length} policy violation(s) in gate mode`);
    return;
  }

  if (attestationResult === 'FAIL') {
    core.setFailed('AflockGate: attestation verification failed — integrity compromised');
    return;
  }
}

async function actionMain(): Promise<void> {
  try {
    const token = process.env.GITHUB_TOKEN || core.getInput('github-token', { required: false }) || '';
    if (!token) {
      core.setFailed('GITHUB_TOKEN is required');
      return;
    }

    await run({
      ghClient: new ActionsGitHubClient(token),
      repoRoot: process.env.GITHUB_WORKSPACE || process.cwd(),
      signingKeyB64: process.env.AFLOCK_SIGNING_KEY_B64 || core.getInput('signing-key') || undefined,
      openaiKey: process.env.OPENAI_API_KEY || core.getInput('openai-api-key') || undefined,
      anthropicKey: process.env.ANTHROPIC_API_KEY || core.getInput('anthropic-api-key') || undefined,
      policyPath: core.getInput('policy-path') || '.aflock.json',
      outputDir: path.join(process.env.GITHUB_WORKSPACE || process.cwd(), 'aflockgate-artifacts'),
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    core.setFailed(`AflockGate failed: ${msg}`);
  }
}

if (require.main === module || process.env.GITHUB_ACTIONS) {
  actionMain();
}
