import { processDiff, hashContent } from '../src/diff';

describe('processDiff', () => {
  it('returns diff unchanged when under limit', () => {
    const raw = 'diff --git a/file.ts\n+added line\n-removed line';
    const result = processDiff(raw, 10_000);
    expect(result.truncated).toBe(false);
    expect(result.diff).toBe(raw);
    expect(result.originalBytes).toBe(Buffer.byteLength(raw, 'utf-8'));
    expect(result.sha256).toMatch(/^[a-f0-9]{64}$/);
  });

  it('truncates diff exceeding maxBytes', () => {
    const line = 'x'.repeat(100) + '\n';
    const raw = line.repeat(100); // ~10100 bytes
    const result = processDiff(raw, 500);

    expect(result.truncated).toBe(true);
    expect(Buffer.byteLength(result.diff, 'utf-8')).toBeLessThan(result.originalBytes);
    expect(result.diff).toContain('[AflockGate: diff truncated');
    expect(result.originalBytes).toBe(Buffer.byteLength(raw, 'utf-8'));
  });

  it('truncates at a newline boundary', () => {
    const raw = 'line1\nline2\nline3\nline4\n' + 'x'.repeat(1000);
    const result = processDiff(raw, 30);
    expect(result.truncated).toBe(true);
    const mainContent = result.diff.split('\n\n[AflockGate:')[0];
    expect(mainContent.endsWith('\n')).toBe(false);
    expect(mainContent).not.toContain('x'.repeat(100));
  });

  it('produces consistent sha256 for same input', () => {
    const raw = 'hello world';
    const r1 = processDiff(raw, 10_000);
    const r2 = processDiff(raw, 10_000);
    expect(r1.sha256).toBe(r2.sha256);
  });

  it('produces different sha256 for different input', () => {
    const r1 = processDiff('hello', 10_000);
    const r2 = processDiff('world', 10_000);
    expect(r1.sha256).not.toBe(r2.sha256);
  });
});

describe('hashContent', () => {
  it('produces a 64-char hex hash', () => {
    const hash = hashContent('test content');
    expect(hash).toMatch(/^[a-f0-9]{64}$/);
  });

  it('is deterministic', () => {
    expect(hashContent('foo')).toBe(hashContent('foo'));
  });
});
