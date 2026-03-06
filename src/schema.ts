import { z } from 'zod';

export const ReviewIssueSchema = z.object({
  title: z.string(),
  detail: z.string(),
  files: z.array(z.string()),
});

export const TestPlanItemSchema = z.object({
  type: z.enum(['unit', 'integration', 'e2e', 'perf', 'security']),
  what: z.string(),
});

export const LLMReviewSchema = z.object({
  summary: z.string(),
  blocking: z.array(ReviewIssueSchema),
  nonBlocking: z.array(ReviewIssueSchema),
  testPlan: z.array(TestPlanItemSchema),
});

export type LLMReview = z.infer<typeof LLMReviewSchema>;
export type ReviewIssue = z.infer<typeof ReviewIssueSchema>;
export type TestPlanItem = z.infer<typeof TestPlanItemSchema>;

export const PolicySchema = z.object({
  allowedFileGlobs: z.array(z.string()).default(['**/*']),
  deniedFileGlobs: z.array(z.string()).default([]),
  maxChangedFiles: z.number().int().positive().default(100),
  maxDiffBytes: z.number().int().positive().default(500_000),
  llm: z.object({
    provider: z.enum(['openai', 'anthropic', 'mock']).default('mock'),
    model: z.string().default('gpt-4o'),
  }).default({}),
  mode: z.enum(['advisory', 'gate']).default('advisory'),
});

export type Policy = z.infer<typeof PolicySchema>;

export const SAFE_FALLBACK_REVIEW: LLMReview = {
  summary: 'LLM review output was invalid; this is a safe fallback.',
  blocking: [],
  nonBlocking: [],
  testPlan: [{ type: 'unit', what: 'Verify core logic with unit tests' }],
};

export function parseReview(raw: unknown): { review: LLMReview; valid: boolean } {
  const result = LLMReviewSchema.safeParse(raw);
  if (result.success) {
    return { review: result.data, valid: true };
  }
  return { review: SAFE_FALLBACK_REVIEW, valid: false };
}
