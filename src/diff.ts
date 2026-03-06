import * as crypto from 'crypto';

export interface DiffResult {
  diff: string;
  sha256: string;
  truncated: boolean;
  originalBytes: number;
}

export function processDiff(rawDiff: string, maxBytes: number): DiffResult {
  const originalBytes = Buffer.byteLength(rawDiff, 'utf-8');
  let truncated = false;
  let diff = rawDiff;

  if (originalBytes > maxBytes) {
    truncated = true;
    const buf = Buffer.from(rawDiff, 'utf-8');
    diff = buf.subarray(0, maxBytes).toString('utf-8');
    const lastNewline = diff.lastIndexOf('\n');
    if (lastNewline > 0) {
      diff = diff.substring(0, lastNewline);
    }
    diff += '\n\n[AflockGate: diff truncated from ' + originalBytes + ' to ~' + maxBytes + ' bytes]';
  }

  const sha256 = crypto.createHash('sha256').update(diff, 'utf-8').digest('hex');

  return { diff, sha256, truncated, originalBytes };
}

export function hashContent(content: string): string {
  return crypto.createHash('sha256').update(content, 'utf-8').digest('hex');
}
