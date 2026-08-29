#!/usr/bin/env bash
# Renders one keepachangelog section (spec dist/010) as machine-readable
# JSON (schema v1) on stdout. Same argument convention as
# changelog-extract.sh: a version, or the literal "unreleased".
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CHANGELOG="$SCRIPT_DIR/../CHANGELOG.md"
EXTRACT="$SCRIPT_DIR/changelog-extract.sh"

command -v jq >/dev/null 2>&1 || { echo "changelog-json: jq is required but not installed" >&2; exit 1; }

usage() {
    echo "Usage: $(basename "$0") <version> | unreleased" >&2
    exit 1
}

die() { printf 'changelog-json: %s\n' "$*" >&2; exit 1; }

[ $# -eq 1 ] || usage
[ -f "$CHANGELOG" ] || die "$CHANGELOG not found"

TARGET="$1"

# Date (if any) from the section's own heading line "## [$1] - YYYY-MM-DD" -
# changelog-extract.sh's extract_section discards the heading, so this is
# read separately, straight from the file.
section_date() {
    local target="$1" file="$2"
    awk -v target="$target" '
        /^## \[/ {
            s = index($0, "[") + 1
            e = index($0, "]")
            if (substr($0, s, e - s) == target) {
                rest = substr($0, e + 1)
                if (match(rest, /[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]/)) {
                    print substr(rest, RSTART, RLENGTH)
                }
                found = 1
                exit
            }
        }
        END { exit (found ? 0 : 1) }
    ' "$file"
}

BODY=$("$EXTRACT" "$TARGET") || exit 1

if [ "$TARGET" = "unreleased" ]; then
    # No version lives in the "## [Unreleased]" heading itself - the caller
    # (release.yml, for an rc tag) knows the real tag version and patches
    # the "version" field in afterwards; this script only owns the section
    # contents. See scripts/release.sh's changelog-json preflight, which
    # only cares that this is valid JSON, not what "version" says.
    VERSION_OUT="unreleased"
    DATE_OUT=""
else
    DATE_OUT=$(section_date "$TARGET" "$CHANGELOG") || true
    [ -n "$DATE_OUT" ] || die "version $TARGET has no dated changelog section (expected '## [$TARGET] - YYYY-MM-DD')"
    VERSION_OUT="$TARGET"
fi

# One NDJSON object per bullet (category/breaking/api pre-computed in awk;
# the actual text still goes through jq --arg below - never hand-escaped).
ENTRIES_FILE=$(mktemp)
trap 'rm -f "$ENTRIES_FILE"' EXIT

awk '
    BEGIN {
        cur = ""
        map["### Added"] = "added"; map["### Changed"] = "changed"
        map["### Deprecated"] = "deprecated"; map["### Removed"] = "removed"
        map["### Fixed"] = "fixed"; map["### Security"] = "security"
    }
    /^### / {
        if (!($0 in map)) {
            print "changelog-json: unrecognized changelog section: " $0 > "/dev/stderr"
            exit 1
        }
        cur = map[$0]
        next
    }
    /^[ \t]*$/ { next }
    /^- / {
        if (cur == "") {
            print "changelog-json: bullet outside any ### category: " $0 > "/dev/stderr"
            exit 1
        }
        line = substr($0, 3)
        breaking = 0
        if (line ~ /^\*\*BREAKING\*\* /) { breaking = 1; line = substr(line, 14) }
        api = (line ~ /^API:/) ? 1 : 0
        printf "%s\t%d\t%d\t%s\n", cur, breaking, api, line
        next
    }
    {
        print "changelog-json: malformed changelog line (expected blank, \"### Category\", or \"- entry\"): " $0 > "/dev/stderr"
        exit 1
    }
' <<<"$BODY" | while IFS=$'\t' read -r cat breaking api text; do
    api_json=false; [ "$api" = 1 ] && api_json=true
    breaking_json=false; [ "$breaking" = 1 ] && breaking_json=true
    jq -n --arg cat "$cat" --arg text "$text" --argjson api "$api_json" --argjson breaking "$breaking_json" \
        '{category: $cat, text: $text, api: $api, breaking: $breaking}' >> "$ENTRIES_FILE"
done

jq -n --slurpfile entries "$ENTRIES_FILE" --arg version "$VERSION_OUT" --arg date "$DATE_OUT" '
    {
        schema: 1,
        version: $version,
        date: (if $date == "" then null else $date end),
        sections: {
            added:      [$entries[] | select(.category == "added")      | {text, api, breaking}],
            changed:    [$entries[] | select(.category == "changed")    | {text, api, breaking}],
            deprecated: [$entries[] | select(.category == "deprecated") | {text, api, breaking}],
            removed:    [$entries[] | select(.category == "removed")    | {text, api, breaking}],
            fixed:      [$entries[] | select(.category == "fixed")      | {text, api, breaking}],
            security:   [$entries[] | select(.category == "security")   | {text, api, breaking}]
        }
    }'
