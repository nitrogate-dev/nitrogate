import * as github from '@actions/github';
import * as core from '@actions/core';

export interface PRContext {
  owner: string;
  repo: string;
  repoFullName: string;
  prNumber: number;
  baseSha: string;
  headSha: string;
}

export interface GitHubClient {
  getPRContext(): PRContext;
  getChangedFiles(ctx: PRContext): Promise<string[]>;
  getDiff(ctx: PRContext): Promise<string>;
  postComment(ctx: PRContext, body: string): Promise<void>;
}

export class ActionsGitHubClient implements GitHubClient {
  private octokit;

  constructor(token: string) {
    this.octokit = github.getOctokit(token);
  }

  getPRContext(): PRContext {
    const ctx = github.context;
    if (!ctx.payload.pull_request) {
      throw new Error('This action must be triggered by a pull_request event');
    }
    return {
      owner: ctx.repo.owner,
      repo: ctx.repo.repo,
      repoFullName: `${ctx.repo.owner}/${ctx.repo.repo}`,
      prNumber: ctx.payload.pull_request.number,
      baseSha: ctx.payload.pull_request.base.sha,
      headSha: ctx.payload.pull_request.head.sha,
    };
  }

  async getChangedFiles(ctx: PRContext): Promise<string[]> {
    const files: string[] = [];
    let page = 1;
    while (true) {
      const { data } = await this.octokit.rest.pulls.listFiles({
        owner: ctx.owner,
        repo: ctx.repo,
        pull_number: ctx.prNumber,
        per_page: 100,
        page,
      });
      if (data.length === 0) break;
      files.push(...data.map(f => f.filename));
      if (data.length < 100) break;
      page++;
    }
    return files;
  }

  async getDiff(ctx: PRContext): Promise<string> {
    const { data } = await this.octokit.rest.pulls.get({
      owner: ctx.owner,
      repo: ctx.repo,
      pull_number: ctx.prNumber,
      mediaType: { format: 'diff' },
    });
    return data as unknown as string;
  }

  async postComment(ctx: PRContext, body: string): Promise<void> {
    const MARKER = '<!-- aflockgate-review -->';
    const { data: comments } = await this.octokit.rest.issues.listComments({
      owner: ctx.owner,
      repo: ctx.repo,
      issue_number: ctx.prNumber,
      per_page: 100,
    });

    const existing = comments.find(c => c.body?.includes(MARKER));
    const fullBody = `${MARKER}\n${body}`;

    if (existing) {
      await this.octokit.rest.issues.updateComment({
        owner: ctx.owner,
        repo: ctx.repo,
        comment_id: existing.id,
        body: fullBody,
      });
      core.info(`Updated existing PR comment ${existing.id}`);
    } else {
      await this.octokit.rest.issues.createComment({
        owner: ctx.owner,
        repo: ctx.repo,
        issue_number: ctx.prNumber,
        body: fullBody,
      });
      core.info('Created new PR comment');
    }
  }
}
