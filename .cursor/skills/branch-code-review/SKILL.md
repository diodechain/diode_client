---
name: branch-code-review
description: Use when the user asks to review a branch, review code changes, code review a PR, check branch quality, or evaluate changes against project guidelines.
---

# Branch Code Review

Reviews code changes in the current or specified branch against project guidelines in `AGENTS.md`. Scopes review to new changes only and incorporates existing GitHub PR feedback when a PR exists.

## Prerequisites

- Git repository with a base branch (typically `master` or `origin/master`)
- Optional: [GitHub CLI](https://cli.github.com/) (`gh`) installed and authenticated for PR comments

## Workflow

### 1. Determine scope

- **Current branch**: Use `git diff origin/master...HEAD` or `git diff master...HEAD` for changes
- **Named branch**: Use `git diff origin/master...<branch>` or `git merge-base` then `git diff <base>...<branch>`
- Focus only on files/lines that changed

### 2. Pull GitHub PR comments (if available)

If the branch has an open PR:

```bash
gh pr view --json number,body,title,comments,reviews,url
gh api repos/{owner}/{repo}/pulls/{number}/comments
```

If `gh pr view` succeeds, include:
- PR number and URL
- General PR comments (body, issue comments)
- Inline review comments (path, line, body)

If no PR exists or `gh` is unavailable, continue without PR comments.

### 3. Determine intended goal and review for correctness

**3a. Determine intended goal**

- **From PR**: Use `body` and `title` from `gh pr view`. The PR description often states the goal.
- **From linked issue**: Parse the PR body for issue references (e.g. `Closes #123`, `Fixes #456`, `Resolves #789`). Fetch each referenced issue:
  ```bash
  gh issue view <number>
  ```
  Use the issue title and body as the authoritative goal description when available.
- **Fallback**: If no PR or no goal in PR/issue, infer the goal from the changed code (module names, function changes, tests, commit messages). State clearly that the goal was inferred.

**3b. Correctness review**

Evaluate the changed code for:

1. **Logical correctness and canonicity**: Is the logic sound? Are edge cases handled? Does it use idiomatic patterns (e.g. `with`, pattern matching) rather than convoluted conditionals?
2. **Goal alignment**: Does the implementation actually achieve the intended goal? Are there gaps (e.g. missing validation, wrong branch, incorrect handling) or overreach (e.g. solving problems outside scope)?
3. **Conciseness**: Would a shorter or more direct implementation reach the same goal? If yes, that is a flaw. Prefer minimal, readable code over verbose equivalents.

Report correctness issues in the same format as guideline issues (category, location, explanation).

### 4. Review against guidelines

Read `AGENTS.md` and evaluate the changed code against contained rules.

- **Minimalism**: changes should be minimal, don't repeat code

Do not copy `AGENTS.md` into the review; reference section names and specific rules when citing issues.

### 5. Output structure

Use this exact structure for the review:

```markdown
### Intended goal

[One sentence: state the goal from PR body, linked issue, or inferred from code. If inferred, say so.]

### Issues found

- **[Category]** [Issue]: [File:line or location]. [Brief explanation.]
- ...

[If PR comments were pulled in:]
### GitHub PR comments

- [Author] on `path:line`: [Comment text]
- ...

---

## 2. Score: X/10

[One sentence justifying the score based on AGENTS.md alignment and correctness (logic, goal alignment, conciseness). 10 = exemplary; 1 = major violations.]

---

## 3. LLM prompts to fix issues

[One prompt per issue or group of related issues. Prompts should be copy-pasteable and direct an LLM to fix the specific problem.]

- **Issue [n]**: "In [file], [describe the fix]. Per AGENTS.md [section]."
- ...
```

### 6. Propose posting to GitHub PR

If a PR exists for the branch **and the score is 8 or above**, after outputting the review, **propose** posting it as a comment:

- Ask: "Would you like me to post this review as a comment on the PR?"
- Command: `gh pr comment --body-file -` (pipe the markdown into stdin) or `gh pr comment --body "..."` with the review content
- Only post after the user confirms

If the score is below 8, do not propose posting. Instead suggest the user fix the issues locally first, then run the review again.

### Scoring guide

| Score | Meaning |
|-------|---------|
| 9–10 | Fully aligned; logically correct; reaches goal; minimal code |
| 7–8 | Mostly aligned; fixable issues (guidelines or correctness) |
| 5–6 | Several violations; needs revision |
| 3–4 | Major violations in multiple areas |
| 1–2 | Fundamental guideline or correctness violations |

## Example prompts

**Guideline issue:**
```
In lib/ddrive_web/live/settings_live.ex around line 45, replace the case statement with a with expression per AGENTS.md Elixir guidelines. Prefer :ok = call() when errors don't need user handling.
```

**Correctness issue (conciseness):**
```
In lib/ddrive_web/live/join_zone.ex around line 120, the validation can be done in a single with pipeline instead of nested case statements. Consolidate and return {:error, _} early per project style.
```

## Additional resources

- Guidelines: `AGENTS.md` (project root)
