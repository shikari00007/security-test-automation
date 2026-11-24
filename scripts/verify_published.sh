#!/usr/bin/env bash
# Run ONLY after the repository has been published with maintainer authorization.
# Verifies the exact documented install command against the published GitHub repository.
set -euo pipefail
tmp="$(mktemp -d)"; export HOME="$tmp/home"; mkdir -p "$HOME" "$tmp/proj"; cd "$tmp/proj"
npx -y skills add shikari00007/security-test-automation -a claude-code -a codex -a cursor -a gemini-cli -y --copy
n=$(find . -name SKILL.md | wc -l)
echo "SKILL.md files installed: $n (expected 16 per agent directory)"
for d in .claude/skills .agents/skills; do
  [ -d "$d" ] && echo "$d: $(ls "$d" | wc -l) skills"
done
python3 -m pip --version >/dev/null 2>&1 && true
echo "Now run: security-skills skills validate .agents/skills   (after pip install of the runner)"
