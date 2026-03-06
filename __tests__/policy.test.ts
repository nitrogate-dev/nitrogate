import { evaluatePolicy } from '../src/policy';
import { Policy } from '../src/schema';

function makePolicy(overrides: Partial<Policy> = {}): Policy {
  return {
    allowedFileGlobs: ['**/*'],
    deniedFileGlobs: [],
    maxChangedFiles: 100,
    maxDiffBytes: 500_000,
    llm: { provider: 'mock', model: 'gpt-4o' },
    mode: 'advisory',
    ...overrides,
  };
}

describe('evaluatePolicy', () => {
  it('passes with no violations when files are within allowed globs', () => {
    const policy = makePolicy({ allowedFileGlobs: ['src/**', 'tests/**'] });
    const violations = evaluatePolicy(policy, ['src/main.ts', 'tests/foo.test.ts']);
    expect(violations).toHaveLength(0);
  });

  it('reports files outside allowed globs', () => {
    const policy = makePolicy({ allowedFileGlobs: ['src/**'] });
    const violations = evaluatePolicy(policy, ['src/main.ts', 'infra/deploy.sh']);
    expect(violations).toHaveLength(1);
    expect(violations[0].type).toBe('outside_allowed');
    expect(violations[0].files).toContain('infra/deploy.sh');
  });

  it('reports files matching denied globs', () => {
    const policy = makePolicy({ deniedFileGlobs: ['**/.env', '**/*.pem'] });
    const violations = evaluatePolicy(policy, ['src/main.ts', 'config/.env', 'certs/server.pem']);
    const denied = violations.find(v => v.type === 'denied_file');
    expect(denied).toBeDefined();
    expect(denied!.files).toEqual(['config/.env', 'certs/server.pem']);
  });

  it('reports when changed files exceed maxChangedFiles', () => {
    const policy = makePolicy({ maxChangedFiles: 2 });
    const files = ['a.ts', 'b.ts', 'c.ts'];
    const violations = evaluatePolicy(policy, files);
    expect(violations).toHaveLength(1);
    expect(violations[0].type).toBe('max_changed_files');
    expect(violations[0].message).toContain('3 files');
    expect(violations[0].message).toContain('limit of 2');
  });

  it('returns multiple violation types simultaneously', () => {
    const policy = makePolicy({
      allowedFileGlobs: ['src/**'],
      deniedFileGlobs: ['**/.env'],
      maxChangedFiles: 1,
    });
    const violations = evaluatePolicy(policy, ['src/main.ts', '.env']);
    const types = violations.map(v => v.type);
    expect(types).toContain('max_changed_files');
    expect(types).toContain('denied_file');
    expect(types).toContain('outside_allowed');
  });

  it('allows everything with wildcard glob', () => {
    const policy = makePolicy({ allowedFileGlobs: ['**/*'] });
    const violations = evaluatePolicy(policy, ['any/path/file.ts', 'root.json']);
    expect(violations).toHaveLength(0);
  });

  it('returns no violations for an empty file list', () => {
    const policy = makePolicy();
    const violations = evaluatePolicy(policy, []);
    expect(violations).toHaveLength(0);
  });
});
