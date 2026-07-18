#!/usr/bin/env bash
# Reads sections from CHANGELOG.md (keepachangelog 1.1.0). Used by
# release.sh and (later) CI as a consistency gate (spec dist/003 §4/§6).
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CHANGELOG="$SCRIPT_DIR/../CHANGELOG.md"

usage() {
    echo "Usage: $(basename "$0") <version> | unreleased | --latest-version" >&2
    exit 1
}

# Body of the section "## [$1]" from $2, with leading/trailing blank lines
# trimmed. Exit 1 if the section is missing or (after trimming) empty.
extract_section() {
    local target="$1" file="$2"
    awk -v target="$target" '
        BEGIN { state = 0; found = 0; n = 0 }
        /^## \[/ {
            if (state == 1) { state = 2 }
            else if (state == 0) {
                s = index($0, "[") + 1
                e = index($0, "]")
                if (substr($0, s, e - s) == target) { state = 1; found = 1 }
            }
            next
        }
        state == 1 { n++; body[n] = $0 }
        END {
            if (!found) exit 1
            first = 1; last = n
            # The oldest section has no trailing "## [" line to bound the
            # body - the reference-link block at the end of the file
            # (spec §2) must therefore be cut off explicitly, or it ends up
            # in the extracted body.
            while (last >= first && body[last] ~ /^\[[^]]+\]:/) last--
            while (first <= last && body[first] ~ /^[ \t]*$/) first++
            while (last >= first && body[last] ~ /^[ \t]*$/) last--
            if (first > last) exit 1
            for (i = first; i <= last; i++) print body[i]
        }
    ' "$file"
}

# Topmost release version number (first "## [...]" section other than Unreleased).
# Exit 1 if there is no release section yet.
latest_version() {
    local file="$1"
    awk '
        /^## \[/ {
            s = index($0, "[") + 1
            e = index($0, "]")
            h = substr($0, s, e - s)
            if (h != "Unreleased") { print h; found = 1; exit }
        }
        END { exit (found ? 0 : 1) }
    ' "$file"
}

[ $# -eq 1 ] || usage

[ -f "$CHANGELOG" ] || { echo "changelog-extract: $CHANGELOG not found" >&2; exit 1; }

case "$1" in
    --latest-version)
        latest_version "$CHANGELOG" \
            || { echo "changelog-extract: no release section in $CHANGELOG" >&2; exit 1; }
        ;;
    unreleased)
        extract_section "Unreleased" "$CHANGELOG" \
            || { echo "changelog-extract: [Unreleased] is missing or empty" >&2; exit 1; }
        ;;
    *)
        extract_section "$1" "$CHANGELOG" \
            || { echo "changelog-extract: section [$1] is missing or empty in $CHANGELOG" >&2; exit 1; }
        ;;
esac
