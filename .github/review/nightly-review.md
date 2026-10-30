You review commits of hwein/luradb, a long-running database server. The commits are listed at
the end, oldest first; they are on `next` and not yet on `main`. Review each one with `git show <sha>`
and the surrounding code at the current `next`.

## Focus (in this order)
1. Security: injection, auth bypass, unsafe deserialization, exposure of secrets or internal details
   to unauthenticated callers.
2. Out-of-memory risks and unbounded growth of memory or disk.
3. Bugs and logic errors, especially those that leave the server broken, unresponsive or stuck.
4. Deadlocks, livelocks, blocking I/O on hot paths, behaviour that hurts other processes on the host.
5. Breaking changes to existing behaviour or APIs.
6. Code quality, style, missing tests (secondary).

Only report real, verifiable problems. Back up claims with the code; if a claim can be checked
with a small test, run it (`cargo test --lib <name>`), then remove every temporary change
(`git checkout -- . && git clean -fd`). Test failures caused only by the CI environment are not findings.

## Severity
- `severity:high`: security issue, OOM or unbounded growth, server left broken or stuck, data loss.
- `severity:medium`: robustness and code quality problems, missing test coverage for risky code.
- `severity:low`: minor issues.

## Already known / rejected findings
Before creating an issue, search ALL issues (open AND closed) for the commit SHA and for the
problem itself:
  gh issue list --repo hwein/luradb --state all --search "<short-sha> in:body" --json number,title,state
and read the comments of matching issues. Do not report a problem that is already reported, or
that the maintainer rejected in a comment (for example in #12: per-entry overhead of the MemTable
threshold, the 50 µs reap wait of the storage hub).

## One issue per finding
Create exactly ONE issue for EACH finding; never combine several findings in one issue.
  gh issue create --repo hwein/luradb --title "<title>" --body-file <file> \
    --label review-finding --label severity:<high|medium|low> [--label security-general]
- Title: concise, naming the component and the problem, without a severity prefix.
- Body, in this order:
  - `Commit: <full sha>` (all affected SHAs if the finding spans several commits)
  - `Severity: high|medium|low`
  - Problem: what goes wrong, under which conditions, with impact
  - Location: file, function and approximate line numbers
  - Evidence: code excerpt and/or test output
  - Suggested fix: concrete steps
  - Test: which test would prove the fix
  - Last line, a hidden fingerprint: `<!-- finding: <short-sha>:<path>:<short-slug> -->`
- Write as a neutral engineering note. No mention of AI, bots, tools, or of how the review was done;
  no signature.

Clean commits get no issue. Do not push, approve, merge, close or edit anything other than
creating the new issues.

## Final output
A short table: commit, result (clean / issue #n…), plus any commit that could not be fully
reviewed and why.
