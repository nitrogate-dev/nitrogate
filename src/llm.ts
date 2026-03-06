import { Policy, LLMReview, parseReview } from './schema';

export interface LLMInput {
  diff: string;
  changedFiles: string[];
  repoFullName: string;
  prNumber: number;
}

export interface LLMResult {
  review: LLMReview;
  valid: boolean;
  provider: string;
  model: string;
}

export interface LLMProvider {
  call(systemPrompt: string, userPrompt: string): Promise<string>;
}

const SYSTEM_PROMPT = `You are an expert code reviewer. You MUST respond with STRICT JSON only — no markdown fences, no commentary outside the JSON object. Use this exact schema:
{
  "summary": "<one paragraph summary of the PR>",
  "blocking": [{"title": "<issue>", "detail": "<explanation>", "files": ["<path>"]}],
  "nonBlocking": [{"title": "<issue>", "detail": "<explanation>", "files": ["<path>"]}],
  "testPlan": [{"type": "unit|integration|e2e|perf|security", "what": "<description>"}]
}
If there are no blocking issues, return an empty array for "blocking". Same for "nonBlocking" and "testPlan".`;

function buildUserPrompt(input: LLMInput): string {
  return `Repository: ${input.repoFullName}
PR #${input.prNumber}
Changed files (${input.changedFiles.length}):
${input.changedFiles.map(f => `  - ${f}`).join('\n')}

Unified diff:
${input.diff}`;
}

export class MockProvider implements LLMProvider {
  async call(_system: string, _user: string): Promise<string> {
    const mockReview: LLMReview = {
      summary: 'Mock review: changes look reasonable. This is a mock provider response for testing.',
      blocking: [],
      nonBlocking: [
        {
          title: 'Consider adding error handling',
          detail: 'Some functions may benefit from explicit error handling.',
          files: ['src/main.ts'],
        },
      ],
      testPlan: [
        { type: 'unit', what: 'Test core business logic' },
        { type: 'integration', what: 'Test end-to-end workflow with mocks' },
      ],
    };
    return JSON.stringify(mockReview);
  }
}

export class OpenAIProvider implements LLMProvider {
  constructor(private apiKey: string, private model: string) {}

  async call(systemPrompt: string, userPrompt: string): Promise<string> {
    const res = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${this.apiKey}`,
      },
      body: JSON.stringify({
        model: this.model,
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userPrompt },
        ],
        temperature: 0.2,
        max_tokens: 4096,
      }),
    });

    if (!res.ok) {
      throw new Error(`OpenAI API error: ${res.status} ${res.statusText}`);
    }

    const data = (await res.json()) as { choices: { message: { content: string } }[] };
    return data.choices[0].message.content;
  }
}

export class AnthropicProvider implements LLMProvider {
  constructor(private apiKey: string, private model: string) {}

  async call(systemPrompt: string, userPrompt: string): Promise<string> {
    const res = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': this.apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: this.model,
        system: systemPrompt,
        messages: [{ role: 'user', content: userPrompt }],
        max_tokens: 4096,
      }),
    });

    if (!res.ok) {
      throw new Error(`Anthropic API error: ${res.status} ${res.statusText}`);
    }

    const data = (await res.json()) as { content: { text: string }[] };
    return data.content[0].text;
  }
}

export function createProvider(policy: Policy, secrets: { openaiKey?: string; anthropicKey?: string }): LLMProvider {
  switch (policy.llm.provider) {
    case 'mock':
      return new MockProvider();
    case 'openai':
      if (!secrets.openaiKey) throw new Error('OpenAI API key required but not provided');
      return new OpenAIProvider(secrets.openaiKey, policy.llm.model);
    case 'anthropic':
      if (!secrets.anthropicKey) throw new Error('Anthropic API key required but not provided');
      return new AnthropicProvider(secrets.anthropicKey, policy.llm.model);
    default:
      return new MockProvider();
  }
}

export async function runLLMReview(provider: LLMProvider, input: LLMInput, policy: Policy): Promise<LLMResult> {
  const userPrompt = buildUserPrompt(input);
  const rawResponse = await provider.call(SYSTEM_PROMPT, userPrompt);

  let parsed: unknown;
  try {
    parsed = JSON.parse(rawResponse);
  } catch {
    const { review } = parseReview(null);
    return { review, valid: false, provider: policy.llm.provider, model: policy.llm.model };
  }

  const { review, valid } = parseReview(parsed);
  return { review, valid, provider: policy.llm.provider, model: policy.llm.model };
}
