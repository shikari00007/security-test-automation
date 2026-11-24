#!/usr/bin/env bash
# Verifies the documented install command against the PUBLISHED GitHub repository (needs network + Node.js).
# Usage: scripts/verify_published.sh [owner/repo]    (default: shikari00007/security-test-automation)
set -euo pipefail
repo="${1:-shikari00007/security-test-automation}"
tmp="$(mktemp -d)"; export HOME="$tmp/home"; mkdir -p "$HOME" "$tmp/proj"; cd "$tmp/proj"
npx -y skills add "$repo" -y
n=$(find .agents/skills -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)
echo "skills installed into .agents/skills: $n"
[ "$n" -eq 16 ] || { echo "FAIL: expected 16 skills" >&2; exit 1; }
for d in .agents/skills/*; do test -f "$d/SKILL.md" || { echo "FAIL: $d has no SKILL.md" >&2; exit 1; }; done
echo "OK: $repo installs 16 skills"
