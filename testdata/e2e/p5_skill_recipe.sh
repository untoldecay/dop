#!/usr/bin/env bash
# P5 end-to-end: skill file + docs recipes are well-formed and runnable.
# Focus: structural checks (skill has required sections, recipes reference
# real DOP commands). The full "does Claude Code load and use it" is out
# of automated scope.

set -euo pipefail

DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "P5 e2e: no dop at $DOP" >&2; exit 2; }

pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

SKILL=./skills/claude-code/SKILL.md
RECIPES=./docs/RECIPES.md

echo "=== [1] skill file exists and is non-trivial"
[[ -f "$SKILL" ]] || fail "SKILL.md missing at $SKILL"
[[ $(wc -l < "$SKILL") -gt 20 ]] || fail "SKILL.md suspiciously short"
pass "skill file present"

echo "=== [2] YAML frontmatter with name + description"
# Frontmatter must be at file top: --- ... ---
head -1 "$SKILL" | grep -q "^---" || fail "no opening --- for frontmatter"
awk 'NR==1&&/^---/{f=1;next} f&&/^---/{exit} f' "$SKILL" | grep -q "^name:" || fail "no name: in frontmatter"
awk 'NR==1&&/^---/{f=1;next} f&&/^---/{exit} f' "$SKILL" | grep -qi "^description: Use when" || fail "description must start with 'Use when'"
pass "frontmatter present with name + 'Use when' description"

echo "=== [3] skill covers the DOP-specific essentials"
# These aren't format requirements — they're content requirements for THIS skill
grep -q -- "dop exec" "$SKILL" || fail "skill doesn't mention the dop exec command"
grep -qi "do not\|don't\|never" "$SKILL" || fail "skill lacks any negative-guidance section"
pass "essential dop-usage content present"

echo "=== [3] recipes doc exists with the three harnesses"
[[ -f "$RECIPES" ]] || fail "RECIPES.md missing"
for h in "Shell / cron" "Claude Code" "Buzz-style" "Auditing"; do
    grep -q "## $h" "$RECIPES" || fail "RECIPES.md missing section: $h"
done
pass "recipes cover shell, Claude, Buzz, audit"

echo "=== [4] every dop invocation in RECIPES is a real subcommand"
# Extract lines starting with `dop ` and check the subcommand exists.
# We accept: init, encrypt, exec, whoami, env, pull, push, token, log, merge-driver, help
KNOWN_SUBCOMMANDS='(init|encrypt|exec|whoami|env|pull|push|token|log|merge-driver|help)'
bad=0
while IFS= read -r line; do
    # strip leading whitespace and ANSI
    line=$(echo "$line" | sed 's/^[[:space:]]*//')
    # match `dop <subcommand>` where subcommand is a real one
    if [[ "$line" =~ ^dop\ ([a-zA-Z-]+) ]]; then
        cmd="${BASH_REMATCH[1]}"
        if ! echo "$cmd" | grep -qE "^$KNOWN_SUBCOMMANDS\$"; then
            echo "    unknown subcommand referenced: dop $cmd" >&2
            bad=$((bad + 1))
        fi
    fi
done < <(grep -oE 'dop [a-zA-Z-]+' "$RECIPES")
[[ "$bad" -eq 0 ]] || fail "$bad unknown dop subcommands in RECIPES"
pass "all recipe commands reference real subcommands"

echo "=== [5] skill mentions --agent-name and --sign-with"
grep -q -- "--agent-name" "$SKILL" || fail "skill doesn't mention --agent-name"
grep -q -- "--sign-with" "$SKILL" || fail "skill doesn't mention --sign-with"
pass "skill covers both auth modes"

echo "=== [6] skill NEVER tells Claude to type the bearer into chat"
if grep -qEi "paste|type|share.*token" "$SKILL"; then
    # Only fail if the match is about the bearer/token specifically.
    # A "type YES" prompt from the passphrase gate context is fine.
    if grep -qEi "(paste|type|share).*(DOP_TOKEN|bearer|token)" "$SKILL"; then
        fail "skill instructs sharing the bearer!"
    fi
fi
pass "skill does not instruct sharing the bearer"

echo ""
echo "P5 e2e: PASS"
