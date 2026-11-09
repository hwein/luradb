#!/usr/bin/env bash
# Release automation. Modes: final (default), rc, --hotfix.
# Principle: all checks first, then mutations; --dry-run shows the plan
# without changing anything (checks incl. cargo/git-fetch still run for real).
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
CHANGELOG="$REPO_ROOT/CHANGELOG.md"
CARGO_TOML="$REPO_ROOT/Cargo.toml"
EXTRACT="$SCRIPT_DIR/changelog-extract.sh"
CHANGELOG_JSON="$SCRIPT_DIR/changelog-json.sh"

DRY_RUN=0
MODE="final"
REPORT=""

# The handbook at docs.luradb.org and the website at luradb.org follow final
# releases: the Release workflow of each fetches everything it needs from the
# tag, so a trigger with the tag is enough.
DOCS_REPO="hwein/luradb-docs"
SITE_REPO="hwein/luradb-site"
FOLLOW_WORKFLOW="release.yml"
HANDBOOK=0
HANDBOOK_FAILED=0
WEBSITE=0
WEBSITE_FAILED=0
FOLLOW_TAG=""

TMP_DIRS=()
cleanup() {
    # Save $?: otherwise the trap handler overwrites the script's real exit
    # code with the last status of *its own* commands.
    local rc=$? d
    for d in "${TMP_DIRS[@]}"; do
        rm -rf "$d"
    done
    return "$rc"
}
trap cleanup EXIT

usage() {
    local exit_code="${1:-1}"
    cat <<'EOF'
Usage: scripts/release.sh [rc|--hotfix] [--report <file>] [--dry-run]

  (no argument)    final mode: next -> main, tag vX.Y.Z, next to X.Y.(Z+1)-dev
  rc               rc mode: prerelease tag vX.Y.Z-rc.N on next
  --hotfix         hotfix mode: on hotfix/vX.Y.Z, merge into main, tag vX.Y.Z
  --report <file>  final mode only
  --dry-run        shows the full plan without changing anything

final releases require --report: the JSON report of the release test run against
the rc tag that points at HEAD (fields: tag, commit, verdict)
EOF
    exit "$exit_code"
}

log()  { printf '%s\n' "$*"; }
step() { printf -- '-- %s\n' "$*"; }
die()  { printf 'release.sh: %s\n' "$*" >&2; exit 1; }

current_branch() { git -C "$REPO_ROOT" rev-parse --abbrev-ref HEAD; }

resolve_repo_url() {
    local url
    url=$(git -C "$REPO_ROOT" remote get-url origin)
    url="${url%.git}"
    case "$url" in
        git@github.com:*) url="https://github.com/${url#git@github.com:}" ;;
    esac
    printf '%s' "$url"
}

cargo_version() {
    local v
    v=$(sed -n 's/^version *= *"\([^"]*\)"/\1/p' "$CARGO_TOML" | head -1)
    printf '%s' "${v%%[-+]*}"
}

semver_bump() {
    local base="$1" kind="$2" major minor patch
    IFS='.' read -r major minor patch <<<"$base"
    case "$kind" in
        major) printf '%s.0.0' "$((major + 1))" ;;
        minor) printf '%s.%s.0' "$major" "$((minor + 1))" ;;
        patch) printf '%s.%s.%s' "$major" "$minor" "$((patch + 1))" ;;
    esac
}

# $1 > $2 ? (both X.Y.Z)
version_gt() {
    local a="$1" b="$2"
    [ "$a" = "$b" ] && return 1
    local -a A B
    IFS='.' read -r -a A <<<"$a"
    IFS='.' read -r -a B <<<"$b"
    local i
    for i in 0 1 2; do
        if (( ${A[i]:-0} > ${B[i]:-0} )); then return 0; fi
        if (( ${A[i]:-0} < ${B[i]:-0} )); then return 1; fi
    done
    return 1
}

check_tools() {
    command -v jq >/dev/null 2>&1 || die "jq is required (apt install jq)"
    command -v curl >/dev/null 2>&1 || die "curl is required (apt install curl)"
}

github_api_url() {
    local repo_url
    repo_url=$(resolve_repo_url)
    printf 'https://api.github.com/repos/%s' "${repo_url#https://github.com/}"
}

# The pushed tag only triggers the Release workflow; the GitHub release with
# its assets exists once that workflow has passed. Waits for it (unauthenticated
# API, polled once a minute) and fails loudly when the workflow is red.
wait_for_release_workflow() {
    local tag="$1" api status conclusion html_url assets deadline line
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] wait for the Release workflow of %s and check the GitHub release\n' "$tag"
        return
    fi
    api=$(github_api_url)
    step "waiting for the Release workflow of $tag (up to 45 min)"
    deadline=$(( $(date +%s) + 45 * 60 ))
    status=""
    while :; do
        line=$(curl -fsS "$api/actions/workflows/release.yml/runs?event=push&branch=$tag&per_page=1" \
            | jq -r '.workflow_runs[0] | select(. != null) | [.status, (.conclusion // "-"), .html_url] | @tsv' \
            2>/dev/null || true)
        if [ -n "$line" ]; then
            IFS=$'\t' read -r status conclusion html_url <<<"$line"
            [ "$status" = "completed" ] && break
            log "   workflow $status ..."
        else
            log "   workflow not started yet ..."
        fi
        [ "$(date +%s)" -lt "$deadline" ] || die "the Release workflow of $tag did not finish in time — check ${html_url:-the Actions page}"
        sleep 60
    done
    if [ "$conclusion" != "success" ]; then
        die "the Release workflow of $tag ended with '$conclusion' — no GitHub release was published. Fix the cause on next and cut the next rc. Details: $html_url"
    fi
    assets=$(curl -fsS "$api/releases/tags/$tag" | jq -r '.assets | length' 2>/dev/null || echo 0)
    [ "$assets" -gt 0 ] || die "the Release workflow passed but no GitHub release with assets exists for $tag: $html_url"
    log "Release $tag published with $assets assets: $(resolve_repo_url)/releases/tag/$tag"
}

# Authenticated request to a repository of the follow-up workflows. Prints the
# HTTP status on the first line and the response body after it (status 000: no
# answer). The token only travels through pipes, never through a variable or an
# argument.
repo_api() {
    local -; set +x
    local repo="$1" method="$2" path="$3" body="${4:-}" out
    local -a data=()
    [ -z "$body" ] || data=(--data-raw "$body")
    if out=$(
        printf 'protocol=https\nhost=github.com\n\n' \
            | GCM_INTERACTIVE=never WSLENV="GCM_INTERACTIVE:${WSLENV:-}" GIT_TERMINAL_PROMPT=0 GIT_ASKPASS= \
                timeout 30 git credential fill 2>/dev/null \
            | sed -n 's/^password=\(.*\)$/header = "Authorization: Bearer \1"/p' \
            | curl -sS --max-time 60 --config - -X "$method" \
                -H 'Accept: application/vnd.github+json' \
                "${data[@]}" -w '\n%{http_code}' "https://api.github.com/repos/$repo/$path" 2>/dev/null
    ); then
        printf '%s\n%s' "${out##*$'\n'}" "${out%$'\n'*}"
    else
        printf '000\n'
    fi
}

follow_actions_url() { printf 'https://github.com/%s/actions/workflows/%s' "$1" "$FOLLOW_WORKFLOW"; }

# $1 repository, $2 name for messages, $3 title prefix of the issue the
# workflow opens. Dies when the workflow cannot be started.
check_workflow_access() {
    local repo="$1" label="$2" issue_prefix="$3" resp code body state urls
    resp=$(repo_api "$repo" GET "actions/workflows/$FOLLOW_WORKFLOW")
    code=${resp%%$'\n'*}; body=${resp#*$'\n'}
    [ "$code" = "200" ] \
        || die "cannot read the $label workflow of $repo (HTTP $code): sign in to GitHub with the git credential helper, and check that the workflow exists on main"
    state=$(jq -r '.state // empty' <<<"$body" 2>/dev/null || true)
    [ "$state" = "active" ] || die "the $label workflow Release of $repo is not active (state: ${state:-unknown})"
    log "$label workflow Release: active"
    resp=$(repo_api "$repo" GET 'issues?state=open&per_page=100')
    code=${resp%%$'\n'*}; body=${resp#*$'\n'}
    if [ "$code" = "200" ]; then
        urls=$(jq -r --arg prefix "$issue_prefix" '.[] | select(.pull_request == null and (.title | startswith($prefix))) | .html_url' <<<"$body" 2>/dev/null || true)
        [ -z "$urls" ] || printf 'warning: open "%s" issue:\n%s\n' "$issue_prefix" "$urls" >&2
    fi
}

# Starts the workflow with the tag. Returns 1 when the start failed.
start_workflow() {
    local repo="$1" label="$2" tag="$3" resp code body url
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] start the %s workflow for %s\n' "$label" "$tag"
        return
    fi
    step "starting the $label workflow for $tag"
    resp=$(repo_api "$repo" POST "actions/workflows/$FOLLOW_WORKFLOW/dispatches" "$(jq -nc --arg tag "$tag" '{ref: "main", inputs: {tag: $tag}}')")
    code=${resp%%$'\n'*}; body=${resp#*$'\n'}
    case "$code" in
        204) log "$label workflow started: $(follow_actions_url "$repo")" ;;
        200)
            url=$(jq -r '.html_url // empty' <<<"$body" 2>/dev/null || true)
            log "$label workflow started: ${url:-$(follow_actions_url "$repo")}"
            ;;
        *)
            printf 'release.sh: starting the %s workflow failed (HTTP %s)\n' "$label" "$code" >&2
            return 1
            ;;
    esac
}

# $4 is 1 when the start failed: names the manual start and returns 1 (the tag
# and the release stay).
finish_workflow() {
    local repo="$1" label="$2" issue_title="$3" failed="$4"
    log "Open $label issues: https://github.com/$repo/issues?q=is:open+\"$issue_title\""
    if [ "$failed" -eq 1 ]; then
        printf 'Tag and release are pushed. Start the workflow Release of %s by hand with the tag %s: %s\n' \
            "$repo" "$FOLLOW_TAG" "$(follow_actions_url "$repo")" >&2
        return 1
    fi
}

origin_is_upstream() { [ "$(resolve_repo_url)" = "https://github.com/hwein/luradb" ]; }

# Checks that both workflows can be started, before anything changes.
check_handbook_access() {
    HANDBOOK=0
    if ! origin_is_upstream; then
        log "handbook trigger skipped: origin is not hwein/luradb"
        return
    fi
    HANDBOOK=1
    check_workflow_access "$DOCS_REPO" handbook "Handbook text check for"
}

check_website_access() {
    WEBSITE=0
    if ! origin_is_upstream; then
        log "website trigger skipped: origin is not hwein/luradb"
        return
    fi
    WEBSITE=1
    check_workflow_access "$SITE_REPO" website "Website check for"
}

check_follow_access() {
    check_handbook_access
    check_website_access
}

trigger_handbook() {
    [ "$HANDBOOK" -eq 1 ] || return 0
    FOLLOW_TAG="$1"
    start_workflow "$DOCS_REPO" handbook "$1" || HANDBOOK_FAILED=1
}

trigger_website() {
    [ "$WEBSITE" -eq 1 ] || return 0
    FOLLOW_TAG="$1"
    start_workflow "$SITE_REPO" website "$1" || WEBSITE_FAILED=1
}

# Both starts run even when the first fails.
trigger_follow() {
    trigger_handbook "$1"
    trigger_website "$1"
}

finish_handbook() {
    [ "$HANDBOOK" -eq 1 ] || return 0
    finish_workflow "$DOCS_REPO" handbook "Handbook text check" "$HANDBOOK_FAILED"
}

finish_website() {
    [ "$WEBSITE" -eq 1 ] || return 0
    finish_workflow "$SITE_REPO" website "Website check" "$WEBSITE_FAILED"
}

# Last output of a release: where the issues of both workflows show up, and
# the manual starts of the ones that failed; exit 1 then.
finish_follow() {
    local rc=0
    finish_handbook || rc=1
    finish_website || rc=1
    return "$rc"
}

check_branch() {
    local branch="$1" current
    current=$(current_branch)
    [ "$current" = "$branch" ] || die "must be on $branch (currently: $current)"
}

check_clean_and_synced() {
    git -C "$REPO_ROOT" diff --quiet --ignore-submodules -- \
        || die "working tree not clean (unstaged changes to tracked files)"
    git -C "$REPO_ROOT" diff --quiet --ignore-submodules --cached -- \
        || die "working tree not clean (staged changes)"
    step "git fetch origin"
    git -C "$REPO_ROOT" fetch origin --tags

    local branch upstream local_rev remote_rev base
    branch=$(current_branch)
    upstream="origin/$branch"
    if ! git -C "$REPO_ROOT" rev-parse --verify "$upstream" >/dev/null 2>&1; then
        log "no remote branch $upstream — skipping the behind/diverged check"
        return
    fi
    local_rev=$(git -C "$REPO_ROOT" rev-parse HEAD)
    remote_rev=$(git -C "$REPO_ROOT" rev-parse "$upstream")
    if [ "$local_rev" != "$remote_rev" ]; then
        base=$(git -C "$REPO_ROOT" merge-base HEAD "$upstream")
        if [ "$base" = "$local_rev" ]; then
            die "$branch is behind $upstream — pull first"
        elif [ "$base" != "$remote_rev" ]; then
            die "$branch has diverged from $upstream"
        fi
        # base == remote_rev: local is ahead of $upstream (the normal case
        # for unpushed release commits) — not a violation, no abort.
    fi
}

# The report must be a passing run against an annotated rc tag on exactly HEAD.
check_release_report() {
    [ -n "$REPORT" ] || die "final releases require --report <file> (the release test report)"
    [ -r "$REPORT" ] || die "report not readable: $REPORT"
    local verdict commit tag head
    verdict=$(jq -r '.verdict // empty' "$REPORT") || die "report is not valid JSON: $REPORT"
    commit=$(jq -r '.commit // empty' "$REPORT")
    tag=$(jq -r '.tag // empty' "$REPORT")
    [ "$verdict" = "pass" ] || die "report verdict is not pass: '${verdict}'"
    head=$(git -C "$REPO_ROOT" rev-parse HEAD)
    [ "$commit" = "$head" ] || die "report commit '${commit}' is not HEAD ($head)"
    [ -n "$tag" ] || die "report has no tag"
    [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+-rc\.[0-9]+$ ]] \
        || die "report tag '${tag}' is not an rc tag (vX.Y.Z-rc.N)"
    [ "$(git -C "$REPO_ROOT" cat-file -t "refs/tags/$tag" 2>/dev/null)" = "tag" ] \
        || die "report tag '${tag}' is not an annotated tag"
    [ "$(git -C "$REPO_ROOT" rev-parse "refs/tags/$tag^{commit}")" = "$commit" ] \
        || die "report tag '${tag}' does not point at the report commit"
}

check_tests() {
    step "cargo check --tests"
    ( cd "$REPO_ROOT" && cargo check --tests )
    step "cargo test"
    ( cd "$REPO_ROOT" && cargo test )
}

check_unreleased_nonempty() {
    "$EXTRACT" unreleased >/dev/null || die "[Unreleased] is missing or empty"
}

# Runs unconditionally, even under --dry-run: changelog-json.sh only reads
# CHANGELOG.md, it mutates nothing.
check_changelog_json() {
    "$CHANGELOG_JSON" unreleased | jq empty || die "changelog-json.sh unreleased did not produce valid JSON"
}

check_tag_free() {
    local tag="$1"
    git -C "$REPO_ROOT" rev-parse -q --verify "refs/tags/$tag" >/dev/null && die "tag $tag already exists"
    return 0
}

# Categories in the [Unreleased] section -> bump kind (0.x vs. 1.0+ rules).
bump_kind() {
    local base="$1" body="$2" major has_breaking=0 has_feature=0
    major=${base%%.*}
    grep -qE '^- \*\*BREAKING\*\*' <<<"$body" && has_breaking=1
    grep -qE '^### (Added|Changed|Deprecated|Removed)$' <<<"$body" && has_feature=1
    if [ "$major" -ge 1 ]; then
        if [ "$has_breaking" -eq 1 ]; then echo major; return; fi
        if [ "$has_feature" -eq 1 ]; then echo minor; return; fi
        echo patch
    else
        if [ "$has_feature" -eq 1 ]; then echo minor; return; fi
        echo patch
    fi
}

# Prints the version proposal (unrelated to Cargo.toml's -dev suffix, except
# for the first release: then Cargo.toml's version verbatim, no bump).
propose_version() {
    local last body kind
    if last=$("$EXTRACT" --latest-version 2>/dev/null); then
        body=$("$EXTRACT" unreleased)
        kind=$(bump_kind "$last" "$body")
        semver_bump "$last" "$kind"
    else
        if git -C "$REPO_ROOT" tag -l 'v[0-9]*.[0-9]*.[0-9]*' | grep -vE -- '-rc\.' | grep -q .; then
            die "no release in changelog, but release tags exist — inconsistent state"
        fi
        cargo_version
    fi
}

confirm_version() {
    local proposed="$1" last="$2" input final
    if [ "$DRY_RUN" -eq 1 ]; then
        printf 'Version proposal: %s (dry-run: accepted automatically)\n' "$proposed" >&2
        printf '%s' "$proposed"
        return
    fi
    printf 'Version proposal: %s — press Enter to confirm, or type your own version (X.Y.Z): ' "$proposed" >&2
    IFS= read -r input || true
    final="${input:-$proposed}"
    [[ "$final" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "invalid version: $final (expected X.Y.Z)"
    if [ -n "$last" ] && ! version_gt "$final" "$last"; then
        die "version $final is not greater than the last release $last"
    fi
    printf '%s' "$final"
}

# Removes category blocks ("### Name" + content) that have no bullet content.
filter_empty_categories() {
    awk '
        function flush() { if (cat != "" && hascontent) printf "%s", block }
        /^### / { flush(); cat = $0; block = $0 "\n"; hascontent = 0; next }
        { if ($0 !~ /^[ \t]*$/) hascontent = 1; block = block $0 "\n" }
        END { flush() }
    '
}

# Rebuilds CHANGELOG.md: [Unreleased] -> [$1] - today, fresh empty
# [Unreleased], reference block regenerated from scratch.
_rewrite_changelog_for_release() {
    local version="$1" date body repo_url tmp
    date=$(date +%F)
    body=$("$EXTRACT" unreleased | filter_empty_categories)
    repo_url=$(resolve_repo_url)

    tmp=$(mktemp -d)
    TMP_DIRS+=("$tmp")

    awk '/^## \[Unreleased\]/ { exit } { print }' "$CHANGELOG" > "$tmp/pre"

    awk 'BEGIN{p=0} /^## \[Unreleased\]/{p=1;next} p==1 && /^## \[/{print; p=2; next} p==2{print}' \
        "$CHANGELOG" > "$tmp/rest"

    # Split off the reference block (trailing "[x]: ..." lines incl. preceding blank line).
    awk '
        { lines[NR] = $0; last = NR }
        END {
            end = last
            while (end >= 1 && lines[end] ~ /^\[[^]]+\]:/) end--
            while (end >= 1 && lines[end] ~ /^[ \t]*$/) end--
            for (i = 1; i <= end; i++) print lines[i]
        }
    ' "$tmp/rest" > "$tmp/rest_no_refs"

    mapfile -t existing_versions < <(
        grep -oE '^## \[[0-9]+\.[0-9]+\.[0-9]+\]' "$tmp/rest_no_refs" | sed -E 's/^## \[(.*)\]/\1/'
    )

    {
        printf '[unreleased]: %s/compare/v%s...HEAD\n' "$repo_url" "$version"
        prev_v="$version"
        for v in "${existing_versions[@]}"; do
            printf '[%s]: %s/compare/v%s...v%s\n' "$prev_v" "$repo_url" "$v" "$prev_v"
            prev_v="$v"
        done
        printf '[%s]: %s/releases/tag/v%s\n' "$prev_v" "$repo_url" "$prev_v"
    } > "$tmp/refs"

    {
        cat "$tmp/pre"
        printf '## [Unreleased]\n\n'
        printf '## [%s] - %s\n\n' "$version" "$date"
        printf '%s\n\n' "$body"
        cat "$tmp/rest_no_refs"
        printf '\n'
        cat "$tmp/refs"
    } > "$tmp/final"

    mv "$tmp/final" "$CHANGELOG"
}

finalize_changelog() {
    local version="$1"
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] CHANGELOG.md: [Unreleased] -> [%s] - %s, fresh empty [Unreleased], reference block updated\n' \
            "$version" "$(date +%F)"
        return
    fi
    step "finalizing CHANGELOG.md: [Unreleased] -> [$version]"
    _rewrite_changelog_for_release "$version"
}

set_cargo_version() {
    local new="$1"
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] Cargo.toml version -> %s; cargo check (lockfile sync)\n' "$new"
        return
    fi
    step "Cargo.toml -> $new"
    sed -i "0,/^version = /s/^version = \".*\"/version = \"$new\"/" "$CARGO_TOML"
    ( cd "$REPO_ROOT" && cargo check )
}

# Regenerates api/openapi.json from the current source (dry-run gated like
# set_cargo_version). Written to a temp file first, then moved into place —
# a failed/aborted build (set -e) must never leave a truncated committed file.
regenerate_openapi() {
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] cargo run --quiet -- --dump-openapi -> api/openapi.json\n'
        return
    fi
    step "api/openapi.json regenerate"
    local tmp
    tmp=$(mktemp -d)
    TMP_DIRS+=("$tmp")
    ( cd "$REPO_ROOT" && cargo run --quiet -- --dump-openapi > "$tmp/openapi.json" )
    mv "$tmp/openapi.json" "$REPO_ROOT/api/openapi.json"
}

commit_paths() {
    local message="$1"; shift
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] git commit -m "%s" (%s)\n' "$message" "$*"
        return
    fi
    step "commit: $message"
    git -C "$REPO_ROOT" add "$@"
    git -C "$REPO_ROOT" commit -m "$message"
}

create_tag() {
    local tag="$1" msg="$2"
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] git tag -a %s -m "%s"\n' "$tag" "$msg"
        return
    fi
    step "tag $tag"
    git -C "$REPO_ROOT" tag -a "$tag" -m "$msg"
}

push_atomic() {
    local refs=("$@")
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] git push --atomic origin %s\n' "${refs[*]}"
        return
    fi
    step "push --atomic origin ${refs[*]}"
    if ! git -C "$REPO_ROOT" push --atomic origin "${refs[@]}"; then
        {
            printf 'Push failed. Local commits/tags already exist. Push manually:\n'
            printf '  git push --atomic origin %s\n' "${refs[*]}"
            printf 'A new run of %s will detect this state and perform only the push.\n' "$(basename "$0")"
        } >&2
        exit 1
    fi
}

# Detects: commit/merge/tag/dev-bump already ran, only the push is still
# missing. Prints the affected tag on a match.
detect_pending_push_final() {
    [ "$(current_branch)" = "next" ] || return 1
    local parent tag main_tip
    parent=$(git -C "$REPO_ROOT" rev-parse "HEAD^" 2>/dev/null) || return 1
    tag=$(git -C "$REPO_ROOT" tag --points-at "$parent" -l 'v[0-9]*.[0-9]*.[0-9]*' | grep -vE -- '-rc\.' | head -1)
    [ -n "$tag" ] || return 1
    main_tip=$(git -C "$REPO_ROOT" rev-parse main 2>/dev/null) || return 1
    [ "$main_tip" = "$parent" ] || return 1
    git -C "$REPO_ROOT" ls-remote --exit-code origin "refs/tags/$tag" >/dev/null 2>&1 && return 1
    printf '%s' "$tag"
}

run_final() {
    check_branch next
    check_follow_access

    local resume_tag
    if resume_tag=$(detect_pending_push_final); then
        log "Detected a half-finished release state (tag $resume_tag local, push pending) — catching up the push only."
        push_atomic main next "$resume_tag"
        trigger_follow "$resume_tag"
        finish_follow
        return
    fi

    check_clean_and_synced
    check_release_report
    check_tests
    check_unreleased_nonempty
    check_changelog_json

    local last proposed version tag next_dev
    last=$("$EXTRACT" --latest-version 2>/dev/null || true)
    proposed=$(propose_version)
    version=$(confirm_version "$proposed" "$last")
    tag="v$version"
    check_tag_free "$tag"

    # Mutations start here.
    finalize_changelog "$version"
    set_cargo_version "$version"
    regenerate_openapi
    commit_paths "chore(release): prepare $tag" CHANGELOG.md Cargo.toml Cargo.lock api/openapi.json

    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] git checkout main && git merge --no-ff next -m "chore(release): %s"\n' "$tag"
    else
        step "main: merge --no-ff next"
        git -C "$REPO_ROOT" checkout main
        git -C "$REPO_ROOT" merge --no-ff next -m "chore(release): $tag"
    fi
    create_tag "$tag" "LuraDB $tag"

    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] git checkout next && git merge --ff-only main\n'
    else
        step "next: ff-only main"
        git -C "$REPO_ROOT" checkout next
        git -C "$REPO_ROOT" merge --ff-only main
    fi

    next_dev="$(semver_bump "$version" patch)-dev"
    set_cargo_version "$next_dev"
    regenerate_openapi
    commit_paths "chore(release): begin v$next_dev cycle" Cargo.toml Cargo.lock api/openapi.json

    push_atomic main next "$tag"
    trigger_follow "$tag"
    finish_follow
}

detect_pending_push_rc() {
    [ "$(current_branch)" = "next" ] || return 1
    local head tag
    head=$(git -C "$REPO_ROOT" rev-parse HEAD)
    tag=$(git -C "$REPO_ROOT" tag --points-at "$head" -l 'v[0-9]*.[0-9]*.[0-9]*-rc.*' | head -1)
    [ -n "$tag" ] || return 1
    git -C "$REPO_ROOT" ls-remote --exit-code origin "refs/tags/$tag" >/dev/null 2>&1 && return 1
    printf '%s' "$tag"
}

run_rc() {
    check_branch next

    local resume_tag
    if resume_tag=$(detect_pending_push_rc); then
        log "Detected a half-finished rc state (tag $resume_tag local, push pending) — catching up the push only."
        push_atomic next "$resume_tag"
        wait_for_release_workflow "$resume_tag"
        return
    fi

    check_clean_and_synced
    check_tests
    check_unreleased_nonempty
    check_changelog_json

    local last proposed version n tag
    last=$("$EXTRACT" --latest-version 2>/dev/null || true)
    proposed=$(propose_version)
    version=$(confirm_version "$proposed" "$last")

    n=1
    while git -C "$REPO_ROOT" rev-parse -q --verify "refs/tags/v$version-rc.$n" >/dev/null; do
        n=$((n + 1))
    done
    tag="v$version-rc.$n"
    check_tag_free "$tag"

    # Mutations start here. Changelog stays unfinalized.
    set_cargo_version "$version-rc.$n"
    regenerate_openapi
    commit_paths "chore(release): $tag" Cargo.toml Cargo.lock api/openapi.json
    create_tag "$tag" "LuraDB $tag"
    push_atomic next "$tag"
    wait_for_release_workflow "$tag"
}

detect_pending_push_hotfix() {
    local tag
    tag=$(git -C "$REPO_ROOT" tag --points-at HEAD -l 'v[0-9]*.[0-9]*.[0-9]*' | grep -vE -- '-rc\.' | head -1)
    [ -n "$tag" ] || return 1
    git -C "$REPO_ROOT" ls-remote --exit-code origin "refs/tags/$tag" >/dev/null 2>&1 && return 1
    printf '%s' "$tag"
}

run_hotfix() {
    local branch version major minor patch prev_patch tag

    branch=$(current_branch)
    # A failed push leaves the hotfix run on main, with the new tag on HEAD.
    if [ "$branch" = main ]; then
        check_follow_access
        tag=$(detect_pending_push_hotfix) || die "must be on hotfix/vX.Y.Z (currently: main)"
        log "Detected a half-finished hotfix state (tag $tag local, push pending) — catching up the push only."
        push_atomic main "$tag"
        trigger_follow "$tag"
        log "Don't forget to merge back: git checkout next && git merge main, then delete hotfix/$tag."
        finish_follow
        return
    fi
    [[ "$branch" == hotfix/v* ]] || die "must be on hotfix/vX.Y.Z (currently: $branch)"
    version="${branch#hotfix/v}"
    [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "expected branch name hotfix/vX.Y.Z (currently: $branch)"
    check_follow_access

    IFS='.' read -r major minor patch <<<"$version"
    prev_patch="$major.$minor.$((patch - 1))"
    git -C "$REPO_ROOT" rev-parse -q --verify "refs/tags/v$prev_patch" >/dev/null \
        || die "expected existing release tag v$prev_patch (hotfix branch must branch off from it)"

    check_clean_and_synced
    check_tests
    check_unreleased_nonempty
    check_changelog_json

    tag="v$version"
    check_tag_free "$tag"

    # Mutations start here.
    finalize_changelog "$version"
    set_cargo_version "$version"
    regenerate_openapi
    commit_paths "chore(release): prepare $tag" CHANGELOG.md Cargo.toml Cargo.lock api/openapi.json

    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] git checkout main && git merge --no-ff %s -m "chore(release): %s"\n' "$branch" "$tag"
    else
        step "main: merge --no-ff $branch"
        git -C "$REPO_ROOT" checkout main
        git -C "$REPO_ROOT" merge --no-ff "$branch" -m "chore(release): $tag"
    fi
    create_tag "$tag" "LuraDB $tag"
    push_atomic main "$tag"
    trigger_follow "$tag"

    log ""
    log "Merge back into next (conflicts in Cargo.toml/CHANGELOG.md expected):"
    log "  git checkout next && git merge main"
    log "  cargo run --quiet -- --dump-openapi > api/openapi.json   (restore dev version)"
    log "Then delete $branch: git branch -d $branch"
    finish_follow
}

while [ $# -gt 0 ]; do
    case "$1" in
        rc) MODE="rc" ;;
        --hotfix) MODE="hotfix" ;;
        --dry-run) DRY_RUN=1 ;;
        --report)
            [ $# -ge 2 ] || { printf -- '--report needs a file\n\n' >&2; usage 1; }
            REPORT="$2"
            shift
            ;;
        -h|--help) usage 0 ;;
        *) printf 'Unknown argument: %s\n\n' "$1" >&2; usage 1 ;;
    esac
    shift
done

if [ -n "$REPORT" ] && [ "$MODE" != "final" ]; then
    printf -- '--report applies to final releases only\n\n' >&2
    usage 1
fi

check_tools

case "$MODE" in
    final)  run_final ;;
    rc)     run_rc ;;
    hotfix) run_hotfix ;;
esac
