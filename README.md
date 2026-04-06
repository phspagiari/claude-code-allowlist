# claude-code-allowlist

Auto-approve safe tool calls in Claude Code — with compound command analysis and learning from your approvals.

## The Problem

Claude Code has a [known bug](https://github.com/anthropics/claude-code/issues/28584) where **subagents don't inherit `permissions.allow`** from your settings files. Even if you've carefully configured allowed commands, every subagent still prompts you for approval on every tool call.

On top of that, pattern matching in `permissions.allow` is glob-based — a pattern like `Bash(git log *)` won't match `for repo in a b; do cd "$repo" && git log --oneline; done`, even though it's perfectly safe.

Related issues: [#28584](https://github.com/anthropics/claude-code/issues/28584), [#22665](https://github.com/anthropics/claude-code/issues/22665), [#18950](https://github.com/anthropics/claude-code/issues/18950), [#10906](https://github.com/anthropics/claude-code/issues/10906)

## The Solution

Two hooks that work together:

**`allowlist-approve.py`** (PreToolUse) — Three-phase approval:
1. **Static patterns** from your `permissions.allow` (all settings scopes)
2. **Learned patterns** from `~/.claude/learned-allowlist.json`
3. **Compound command analysis** — decomposes `for`/`while`/`if` loops, `&&`/`||`/`|`/`;` chains, and `$()` subshells, then checks every sub-command against a safe-binaries list

**`allowlist-learn.py`** (PostToolUse) — Learns from manual approvals:
- When you press "yes" to approve a command, the hook extracts patterns and saves them
- Next time a similar command runs, it's auto-approved
- Never learns dangerous binaries (`rm`, `mv`, `chmod`, etc.) or interpreters (`sh`, `python3`, etc.)

```
                    ┌─ settings.json (permissions.allow)
                    ├─ settings.local.json
Phase 1: Patterns ──├─ <project>/.claude/settings.json
                    └─ <project>/.claude/settings.local.json

Phase 2: Learned ─── ~/.claude/learned-allowlist.json

Phase 3: Analysis ── Decompose compound commands, check all binaries
```

## Install

**One-liner (curl):**

```bash
curl -fsSL https://raw.githubusercontent.com/phspagiari/claude-code-allowlist/main/install.sh | bash
```

**Or from a clone:**

```bash
git clone https://github.com/phspagiari/claude-code-allowlist.git
cd claude-code-allowlist
./install.sh
```

**Or ask Claude Code to install it:**

> Install the hooks from https://github.com/phspagiari/claude-code-allowlist

## What Gets Installed

1. `allowlist-approve.py` → `~/.claude/hooks/`
2. `allowlist-learn.py` → `~/.claude/hooks/`
3. `PreToolUse` and `PostToolUse` hook entries in `~/.claude/settings.local.json`

## Compound Command Analysis

The hook decomposes shell syntax and checks every extracted binary:

| Command | Extracted binaries | Result |
|---------|-------------------|--------|
| `for f in *.go; do grep pattern "$f"; done` | `grep` | Approved |
| `cd /tmp && ls -la && cat README.md` | `cd`, `ls`, `cat` | Approved |
| `kubectl get pods \| grep -v Running \| sort` | `kubectl get`, `grep`, `sort` | Approved |
| `VAR=$(git rev-parse HEAD) && echo $VAR` | `git rev-parse`, `echo` | Approved |
| `for f in *.log; do rm "$f"; done` | `rm` | **Blocked** |
| `echo data > /tmp/output.txt` | redirect detected | **Blocked** |
| `find . -exec rm {} \;` | `-exec rm` detected | **Blocked** |
| `sed -i 's/foo/bar/' file.txt` | `sed -i` detected | **Blocked** |

Safety gates apply even when a broad pattern like `Bash(echo *)` matches — redirects, `tee`, `sed -i`, and dangerous `-exec` are always caught.

## Learning

Every time you manually press "yes" to approve a tool call, the PostToolUse hook learns from it:

| What you approve | What gets learned |
|-----------------|-------------------|
| `bazel build //target:all` | `bazel` added as safe binary |
| `git stash pop` | `git stash` added as safe subcommand |
| `mcp__custom__tool` | Exact tool name saved |
| `Read(/path/to/project/file.go)` | Project-root path pattern |

Learned patterns are saved to `~/.claude/learned-allowlist.json`. You can inspect, edit, or delete this file at any time.

**Safety guardrails** — the learning hook never learns:
- Dangerous binaries: `rm`, `mv`, `chmod`, `kill`, `sudo`, etc.
- Interpreters: `sh`, `bash`, `python3`, `node`, etc. (they can run arbitrary code)

## Supported Patterns

All `permissions.allow` pattern formats are supported:

| Pattern | Matches |
|---------|---------|
| `Read` | All Read tool calls |
| `Bash(git log *)` | Bash commands matching the glob |
| `Bash(python3:*)` | Any command starting with `python3` |
| `mcp__slack__channels_list` | Exact MCP tool name |
| `mcp__bigquery__*` | Glob on MCP tool names |
| `Read(//usr/**)` | Read with absolute path prefix |
| `Read(~/path/**)` | Read with home-relative path |
| `WebFetch(domain:github.com)` | WebFetch to specific domain |
| `Skill(name)` | Specific skill invocation |
| `Agent(type)` | Specific subagent type |

## Example Configuration

See [`settings.example.json`](settings.example.json) for a starter set of read-only patterns you can add to your `~/.claude/settings.local.json`.

## Testing

```bash
# Should output JSON with permissionDecision: allow
echo '{"tool_name":"Bash","tool_input":{"command":"git log --oneline"}}' | python3 ~/.claude/hooks/allowlist-approve.py

# Compound command — also approved
echo '{"tool_name":"Bash","tool_input":{"command":"for f in *.go; do grep TODO \"$f\"; done"}}' | python3 ~/.claude/hooks/allowlist-approve.py

# Should produce no output (dangerous)
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' | python3 ~/.claude/hooks/allowlist-approve.py
```

## Uninstall

```bash
rm ~/.claude/hooks/allowlist-approve.py ~/.claude/hooks/allowlist-learn.py
rm ~/.claude/learned-allowlist.json
```

Then remove the `PreToolUse` and `PostToolUse` hook entries from `~/.claude/settings.local.json`.

## Requirements

- Python 3 (standard library only, no dependencies)
- Claude Code

## License

MIT
