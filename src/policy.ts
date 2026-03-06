import * as fs from 'fs';
import * as path from 'path';
import { minimatch } from 'minimatch';
import { Policy, PolicySchema } from './schema';

export interface PolicyViolation {
  type: 'denied_file' | 'outside_allowed' | 'max_changed_files';
  message: string;
  files?: string[];
}

export interface PolicyResult {
  policy: Policy;
  violations: PolicyViolation[];
  fromFile: boolean;
}

const DEFAULT_POLICY: Policy = {
  allowedFileGlobs: ['**/*'],
  deniedFileGlobs: ['**/.env', '**/*.pem', '**/*.key', '**/credentials.json'],
  maxChangedFiles: 100,
  maxDiffBytes: 500_000,
  llm: { provider: 'mock', model: 'gpt-4o' },
  mode: 'advisory',
};

export function loadPolicy(repoRoot: string, policyPath: string = '.aflock.json'): { policy: Policy; fromFile: boolean } {
  const fullPath = path.resolve(repoRoot, policyPath);
  if (fs.existsSync(fullPath)) {
    const raw = JSON.parse(fs.readFileSync(fullPath, 'utf-8'));
    const parsed = PolicySchema.parse(raw);
    return { policy: parsed, fromFile: true };
  }
  return { policy: DEFAULT_POLICY, fromFile: false };
}

export function evaluatePolicy(policy: Policy, changedFiles: string[]): PolicyViolation[] {
  const violations: PolicyViolation[] = [];

  if (changedFiles.length > policy.maxChangedFiles) {
    violations.push({
      type: 'max_changed_files',
      message: `PR changes ${changedFiles.length} files, exceeding limit of ${policy.maxChangedFiles}`,
    });
  }

  const deniedFiles = changedFiles.filter(f =>
    policy.deniedFileGlobs.some(glob => minimatch(f, glob))
  );
  if (deniedFiles.length > 0) {
    violations.push({
      type: 'denied_file',
      message: `Files match denied globs: ${deniedFiles.join(', ')}`,
      files: deniedFiles,
    });
  }

  const outsideAllowed = changedFiles.filter(f =>
    !policy.allowedFileGlobs.some(glob => minimatch(f, glob))
  );
  if (outsideAllowed.length > 0) {
    violations.push({
      type: 'outside_allowed',
      message: `Files outside allowed globs: ${outsideAllowed.join(', ')}`,
      files: outsideAllowed,
    });
  }

  return violations;
}
