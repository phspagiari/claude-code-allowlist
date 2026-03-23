# claude-code-allowlist

A [PreToolUse hook](https://docs.claude.dev/en/hooks) that makes `permissions.allow` work for subagents in Claude Code.

## The Problem

Claude Code has a [known bug](https://github.com/anthropics/claude-code/issues/28584) where **subagents don't inherit `permissions.allow`** from your settings files. Even if you've carefully configured allowed commands in `settings.json`, every subagent will still prompt you for approval on every single tool call.

Related issues: [#28584](https://github.com/anthropics/claude-code/issues/28584), [#22665](https://github.com/anthropics/claude-code/issues/22665), [#18950](https://github.com/anthropics/claude-code/issues/18950), [#10906](https://github.com/anthropics/claude-code/issues/10906)

## The Solution

This hook reads your existing `permissions.allow` from all settings scopes and auto-approves matching tool calls at the hook level. Hooks **do** propagate to subagents, so your permissions work everywhere — no duplicate configuration needed.

```
settings.json (permissions.allow)  ──┐
settings.local.json                  ├──> hook reads all ──> auto-approves in main + subagents
<project>/.claude/settings.json      │
<project>/.claude/settings.local.json┘
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

> Install the PreToolUse hook from https://github.com/phspagiari/claude-code-allowlist

## What it Does

The install script:

1. Copies `allowlist-approve.py` to `~/.claude/hooks/`
2. Adds a `PreToolUse` hook entry to `~/.claude/settings.local.json`

After install, any pattern in `permissions.allow` across your settings files will be auto-approved for both the main session and all subagents.

## How it Works

When Claude Code calls a tool, the hook:

1. Reads `permissions.allow` from all settings files (user + project level)
2. Checks if the tool call matches any allow pattern
3. If matched → outputs `permissionDecision: allow` → **skips the prompt**
4. If not matched → exits silently → **normal permission flow** (you get prompted)

The hook **never overrides deny rules** — Claude Code evaluates deny before hooks.

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

After install, verify it works:

```bash
# Should output JSON with permissionDecision: allow
echo '{"tool_name":"Bash","tool_input":{"command":"git log --oneline"}}' | python3 ~/.claude/hooks/allowlist-approve.py

# Should produce no output (not in allowlist)
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' | python3 ~/.claude/hooks/allowlist-approve.py
```

## Uninstall

```bash
rm ~/.claude/hooks/allowlist-approve.py
```

Then remove the `PreToolUse` hook entry referencing `allowlist-approve.py` from `~/.claude/settings.local.json`.

## Requirements

- Python 3 (standard library only, no dependencies)
- Claude Code

## License

MIT
