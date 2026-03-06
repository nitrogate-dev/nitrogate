import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import nacl from 'tweetnacl';
import { run, RunDeps } from '../src/main';
import { GitHubClient, PRContext } from '../src/github';

// Capture @actions/core calls
const mockSetOutput = jest.fn();
const mockSetFailed = jest.fn();
const mockInfo = jest.fn();
const mockWarning = jest.fn();
const mockError = jest.fn();

jest.mock('@actions/core', () => ({
  info: (...args: unknown[]) => mockInfo(...args),
  warning: (...args: unknown[]) => mockWarning(...args),
  error: (...args: unknown[]) => mockError(...args),
  setOutput: (name: string, value: string) => mockSetOutput(name, value),
  setFailed: (msg: string) => mockSetFailed(msg),
  getInput: () => '',
}));

class MockGitHubClient implements GitHubClient {
  public postedComment: string = '';

  getPRContext(): PRContext {
    return {
      owner: 'test-owner',
      repo: 'test-repo',
      repoFullName: 'test-owner/test-repo',
      prNumber: 42,
      baseSha: 'base000',
      headSha: 'head111',
    };
  }

  async getChangedFiles(): Promise<string[]> {
    return ['src/main.ts', 'src/utils.ts'];
  }

  async getDiff(): Promise<string> {
    return `diff --git a/src/main.ts b/src/main.ts
--- a/src/main.ts
+++ b/src/main.ts
@@ -1,3 +1,4 @@
+import { foo } from './foo';
 const x = 1;
 const y = 2;
-export default x + y;
+export default foo(x, y);`;
  }

  async postComment(_ctx: PRContext, body: string): Promise<void> {
    this.postedComment = body;
  }
}

describe('integration: full run with mock LLM and signing', () => {
  let tmpDir: string;
  let outputDir: string;
  let signingKeyB64: string;
  let mockClient: MockGitHubClient;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aflockgate-test-'));
    outputDir = path.join(tmpDir, 'artifacts');
    mockClient = new MockGitHubClient();

    const seed = nacl.randomBytes(32);
    signingKeyB64 = Buffer.from(seed).toString('base64');

    jest.clearAllMocks();
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('produces artifacts, posts comment with Attestation: PASS', async () => {
    const deps: RunDeps = {
      ghClient: mockClient,
      repoRoot: tmpDir,
      signingKeyB64,
      openaiKey: undefined,
      anthropicKey: undefined,
      policyPath: '.aflock.json',
      outputDir,
    };

    await run(deps);

    expect(fs.existsSync(path.join(outputDir, 'review.json'))).toBe(true);
    expect(fs.existsSync(path.join(outputDir, 'evidence.json'))).toBe(true);
    expect(fs.existsSync(path.join(outputDir, 'attestation.json'))).toBe(true);

    const review = JSON.parse(fs.readFileSync(path.join(outputDir, 'review.json'), 'utf-8'));
    expect(review.summary).toBeTruthy();
    expect(Array.isArray(review.testPlan)).toBe(true);

    const evidence = JSON.parse(fs.readFileSync(path.join(outputDir, 'evidence.json'), 'utf-8'));
    expect(evidence.repo).toBe('test-owner/test-repo');
    expect(evidence.pr).toBe(42);
    expect(evidence.diffSha256).toMatch(/^[a-f0-9]{64}$/);

    const attestation = JSON.parse(fs.readFileSync(path.join(outputDir, 'attestation.json'), 'utf-8'));
    expect(attestation.schemaVersion).toBe('1.0.0');
    expect(attestation.signature).toBeTruthy();

    expect(mockClient.postedComment).toContain('Attestation: PASS');
    expect(mockClient.postedComment).toContain('AflockGate');
    expect(mockClient.postedComment).toContain('do not paste secrets');

    expect(mockSetOutput).toHaveBeenCalledWith('attestation-result', 'PASS');
    expect(mockSetFailed).not.toHaveBeenCalled();
  });

  it('skips attestation when no signing key provided', async () => {
    const deps: RunDeps = {
      ghClient: mockClient,
      repoRoot: tmpDir,
      signingKeyB64: undefined,
      openaiKey: undefined,
      anthropicKey: undefined,
      policyPath: '.aflock.json',
      outputDir,
    };

    await run(deps);

    expect(mockClient.postedComment).toContain('Attestation: SKIPPED');
    expect(mockSetOutput).toHaveBeenCalledWith('attestation-result', 'SKIPPED');
  });

  it('uses custom policy file when provided', async () => {
    const policyContent = {
      allowedFileGlobs: ['src/**'],
      deniedFileGlobs: ['**/.env'],
      maxChangedFiles: 50,
      maxDiffBytes: 100_000,
      llm: { provider: 'mock', model: 'test-model' },
      mode: 'advisory',
    };
    fs.writeFileSync(path.join(tmpDir, 'custom.aflock.json'), JSON.stringify(policyContent));

    const deps: RunDeps = {
      ghClient: mockClient,
      repoRoot: tmpDir,
      signingKeyB64,
      openaiKey: undefined,
      anthropicKey: undefined,
      policyPath: 'custom.aflock.json',
      outputDir,
    };

    await run(deps);

    const evidence = JSON.parse(fs.readFileSync(path.join(outputDir, 'evidence.json'), 'utf-8'));
    expect(evidence.llmModel).toBe('test-model');
    expect(mockSetFailed).not.toHaveBeenCalled();
  });

  it('reports policy violations and fails in gate mode', async () => {
    const policyContent = {
      allowedFileGlobs: ['docs/**'],
      deniedFileGlobs: [],
      maxChangedFiles: 100,
      maxDiffBytes: 500_000,
      llm: { provider: 'mock', model: 'gpt-4o' },
      mode: 'gate',
    };
    fs.writeFileSync(path.join(tmpDir, '.aflock.json'), JSON.stringify(policyContent));

    const deps: RunDeps = {
      ghClient: mockClient,
      repoRoot: tmpDir,
      signingKeyB64,
      openaiKey: undefined,
      anthropicKey: undefined,
      policyPath: '.aflock.json',
      outputDir,
    };

    await run(deps);

    expect(mockClient.postedComment).toContain('Policy Violations');
    expect(mockClient.postedComment).toContain('outside_allowed');
    expect(mockSetFailed).toHaveBeenCalledWith(expect.stringContaining('policy violation'));
  });

  it('does not fail in advisory mode even with violations', async () => {
    const policyContent = {
      allowedFileGlobs: ['docs/**'],
      deniedFileGlobs: [],
      maxChangedFiles: 100,
      maxDiffBytes: 500_000,
      llm: { provider: 'mock', model: 'gpt-4o' },
      mode: 'advisory',
    };
    fs.writeFileSync(path.join(tmpDir, '.aflock.json'), JSON.stringify(policyContent));

    const deps: RunDeps = {
      ghClient: mockClient,
      repoRoot: tmpDir,
      signingKeyB64,
      openaiKey: undefined,
      anthropicKey: undefined,
      policyPath: '.aflock.json',
      outputDir,
    };

    await run(deps);

    expect(mockClient.postedComment).toContain('Policy Violations');
    expect(mockSetFailed).not.toHaveBeenCalled();
  });
});
