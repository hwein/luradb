#!/usr/bin/env bash
# Prints a GitHub dependency-graph snapshot built from Cargo.lock.
#
# GitHub parses Cargo.lock on its own, but that parse has gone stale before and
# then raised Dependabot alerts for crate versions long gone from the lockfile.
# Submitting a snapshot from the real lockfile keeps the graph and its alerts
# in step with what is actually built:
#
#   scripts/dependency-snapshot.sh \
#     | gh api -X POST "repos/<owner>/<repo>/dependency-graph/snapshots" --input -
#
# Needs cargo and jq. Inside GitHub Actions the GITHUB_* variables identify
# commit, ref and run; elsewhere git and placeholders fill in.
set -euo pipefail

cd "$(dirname "$0")/.."

sha="${GITHUB_SHA:-$(git rev-parse HEAD)}"
ref="${GITHUB_REF:-refs/heads/$(git rev-parse --abbrev-ref HEAD)}"
job_id="${GITHUB_RUN_ID:-local}"
correlator="${GITHUB_WORKFLOW:-local}/${GITHUB_JOB:-manual}"
cargo_version="$(cargo --version | awk '{print $2}')"
scanned="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Crates reachable over normal and build edges on any target run or build
# LuraDB; the rest are test-only. "name vX.Y.Z (path)" becomes "name@X.Y.Z".
runtime="$(cargo tree --locked -e normal,build --target all --prefix none -q --format '{p}' \
  | sed -E 's/ v/@/; s/ \(.*//' | sort -u | jq -R . | jq -s .)"

cargo metadata --format-version 1 --locked | jq \
  --arg sha "$sha" --arg ref "$ref" --arg job_id "$job_id" --arg correlator "$correlator" \
  --arg cargo_version "$cargo_version" --arg scanned "$scanned" --argjson runtime "$runtime" '
  .workspace_members as $members
  | (.packages | map({key: .id, value: "pkg:cargo/\(.name)@\(.version)"}) | from_entries) as $purl
  | ([.resolve.nodes[] | select(.id | IN($members[])) | .deps[].pkg] | unique) as $direct
  | {
      version: 0,
      job: {id: $job_id, correlator: $correlator},
      sha: $sha,
      ref: $ref,
      detector: {
        name: "cargo-metadata",
        version: $cargo_version,
        url: "https://doc.rust-lang.org/cargo/commands/cargo-metadata.html"
      },
      scanned: $scanned,
      manifests: {
        "Cargo.lock": {
          name: "Cargo.lock",
          file: {source_location: "Cargo.lock"},
          resolved: (
            [ .resolve.nodes[]
              | select(.id | IN($members[]) | not)
              | ($purl[.id] | ltrimstr("pkg:cargo/")) as $key
              | {
                  key: $key,
                  value: {
                    package_url: $purl[.id],
                    relationship: (if (.id | IN($direct[])) then "direct" else "indirect" end),
                    scope: (if ($key | IN($runtime[])) then "runtime" else "development" end),
                    dependencies: [.deps[].pkg | $purl[.]]
                  }
                }
            ] | from_entries
          )
        }
      }
    }'
