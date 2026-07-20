# Contributing to LuraDB

This guide applies equally to human and AI contributors. It is short and
direct on purpose — the file itself is an example of the standard it
describes: fast, small, no bloat.

## 1. Project philosophy & scope

LuraDB does the small jobs well: fast, small, no bloat — essential
functionality, done well (see [README.md](README.md) for the full
positioning and use cases). It does not aim to grow into Oracle,
PostgreSQL, MySQL, MongoDB, Cassandra or Spark — no analytical
superstructure, no data-warehouse or data-vault substrate underneath. Every
contribution is measured against one sentence:

> Does it make the small case better — without making LuraDB bigger?

Proposals that pull toward the non-goals above get rejected, even when the
code is good. Linux-first is an architectural decision, not a portability
bug to be fixed.

**Feature bar (binding).** A feature must:

- (a) demonstrate a real, provable benefit for the target use case, and
- (b) not already be achievable, de facto, through existing mechanics.

Making that case is the proposer's job, not the maintainer's. Pure
quality-of-life or convenience features without substance get rejected. For
example, "add INNER JOIN" fails the bar as long as the existing LEFT JOIN
mechanics de facto cover INNER semantics (just phrased slightly
differently) — "it would make me happy" is not a benefit.

## 2. Ways to contribute

- **Bug reports** — open an issue with the server version (`GET /version`
  or `luradb --version`), reproduction steps, expected vs. observed
  behavior, and relevant logs.
- **Feature contributions** — open a PR (see §3) and argue the feature bar
  from §1 in writing.
- **Documentation fixes** — open a PR.

The maintainer does not hold design discussions. The written case for the
feature bar from §1 belongs in the PR description (or an issue it links
to). It gets read and decided, not debated.

## 3. Code contributions & CLA

PRs are open: no pre-approval, no mandatory issue, no need to contact the
maintainer first. If you understand the rules and the scope, submit
directly. Rejection stays on the table at any time — a feature PR without a
convincing written case carries that risk alone.

Merge prerequisites, beyond review and a green CI:

- The **CLA is signed** — once, on your first PR. See [CLA.md](CLA.md) for
  the agreement; post a comment with the exact line "I have read and agree
  to the LuraDB CLA" on that PR to sign it.

The CLA preserves the maintainer's ability to dual-license the codebase —
the public Fair Source license plus separate commercial terms — as a whole.
Without it, externally contributed lines would have to be excluded from
that.

## 4. Binding rules

- PRs target `next`, never `main`.
- Commit messages follow [Conventional Commits
  1.0.0](https://www.conventionalcommits.org/en/v1.0.0/): imperative,
  concise, subject line ≤ 72 characters. A body is only needed if it
  explains something the diff doesn't already show. No sprawling messages,
  no tool/AI attribution trailers (no `Co-Authored-By` bot). Reference
  issues with `Fixes #N`, not a narrative.
- Code follows KISS: no over-engineering, no speculative abstractions,
  match the surrounding style. Comments are short and only for what isn't
  obvious. No backwards-compatibility hacks.
- New dependencies need explicit maintainer approval in an issue first
  (with justification); the license must clear the `deny.toml` allowlist.
- `cargo check --tests` and `cargo test` must be green. New behavior comes
  with tests.
- A user-visible change needs a `CHANGELOG.md` entry under `[Unreleased]`
  in the same PR, following the file's existing Keep a Changelog format
  (`API:` / `**BREAKING**` markers where they apply).
- The public repo's language is English — code, comments, docs and commit
  messages.

## 5. What happens to your PR

CI (tests, cargo-deny, Sonar) must be green and the CLA signed; then the
maintainer reads it and decides.

LuraDB is a spare-time project: there are no response-time guarantees, no
obligation to discuss or justify a decision, and no guaranteed review
rounds. PRs and issues that miss the feature bar, the rules or the scope
can be closed without comment.

An accepted PR is merged into `next` and ships with the next release
(`next` merges to `main` on release, tagged, published as a GitHub
release). See [CHANGELOG.md](CHANGELOG.md) and the repository's Releases
page.

## 6. AI-assisted contributions

Explicitly fine. The same rules apply without exception, and you are
responsible for what you submit, however it was produced. Generated bloat
is treated exactly like hand-written bloat: rejected.

## 7. Security

Never report a vulnerability through an issue or PR. Use the reporting path
in [SECURITY.md](SECURITY.md) instead.
