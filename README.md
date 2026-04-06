# claude-code-allowlist

Smart auto-approval for Claude Code tool calls. Understands compound shell commands, learns from your manual approvals, and propagates permissions to subagents.

## The Problem

Three issues make Claude Code permission prompts painful:

1. **Subagents don't inherit `permissions.allow`** ([#28584](https://github.com/anthropics/claude-code/issues/28584), [#22665](https://github.com/anthropics/claude-code/issues/22665), [#18950](https://github.com/anthropics/claude-code/issues/18950), [#10906](https://github.com/anthropics/claude-code/issues/10906)) — even with a well-configured allowlist, every subagent prompts for everything.

2. **Glob patterns can't parse shell syntax** — `Bash(git log *)` won't match `for repo in a b; do cd "$repo" && git log --oneline; done`, even though every command in there is read-only.

3. **No memory between sessions** — you approve `bazel build` once, get prompted again next session. And the next. And the next.

## How It Works

Two [Claude Code hooks](https://docs.claude.dev/en/hooks) that work together:

### `allowlist-approve.py` (PreToolUse)

Runs before every tool call. Three-phase approval:

**Phase 1 — Static Patterns.** Reads `permissions.allow` from all four settings scopes and matches using the same glob/specifier syntax Claude Code uses natively. This is what makes your existing allowlist work inside subagents.

```
~/.claude/settings.json
~/.claude/settings.local.json
<project>/.claude/settings.json
<project>/.claude/settings.local.json
```

**Phase 2 — Learned Patterns.** Checks `~/.claude/learned-allowlist.json`, populated automatically by the learning hook (see below).

**Phase 3 — Compound Command Analysis.** For Bash commands that didn't match any pattern, decomposes the full shell syntax and checks whether every sub-command is safe:

- Splits on `&&`, `||`, `|`, `;`
- Skips `for`/`while`/`if`/`case` headers, processes their bodies
- Recurses into `$()` command substitutions
- Strips quoted strings to avoid false matches on operators
- Checks each extracted binary against a built-in safe list
- Validates subcommands for tools like `git`, `kubectl`, `docker`, `gcloud`, `brew`

**Safety Veto.** Even when a Phase 1/2 pattern matches, the hook still blocks:

- Output redirections to files (`>`, `>>` — but allows `>/dev/null` and `>&2`)
- `sed -i` (in-place file edit)
- `awk -i inplace`
- `tee` (writes to files)
- `find -exec`/`-execdir` with dangerous binaries
- `xargs` with dangerous binaries

### `allowlist-learn.py` (PostToolUse)

Runs after every tool call. When you manually press "yes" to approve something, this hook extracts patterns and saves them so the same kind of call is auto-approved next time.

**How it knows you pressed "yes":** The PreToolUse hook writes a tracking marker (an md5 hash file in `/tmp/`) when it auto-approves. If PostToolUse runs and finds no marker, it means the user approved manually — time to learn.

**What it learns:**

| Approval | Learned as |
|----------|-----------|
| `bazel build //target:all` | `bazel` as safe binary → matches `bazel test`, `bazel query`, etc. |
| `terraform plan -out=tf.plan` | `terraform` as safe binary |
| `git stash pop` | `git stash` as safe subcommand (not all of git) |
| `kubectl apply -f manifest.yaml` | `kubectl apply` as safe subcommand |
| `npm run build` | `npm run` as safe subcommand |
| `mcp__custom__my_tool` | Exact MCP tool name |
| `Read(/path/to/project/src/main.go)` | `Read(//path/to/project/**)` (project-root pattern) |

**What it never learns:**

| Category | Binaries | Why |
|----------|----------|-----|
| Dangerous | `rm`, `rmdir`, `mv`, `chmod`, `chown`, `chgrp`, `mkfs`, `fdisk`, `dd`, `shred`, `kill`, `killall`, `pkill`, `reboot`, `shutdown`, `sudo`, `su`, `doas` | Destructive or privilege-escalating |
| Interpreters | `sh`, `bash`, `zsh`, `dash`, `fish`, `python`, `python3`, `node`, `deno`, `bun`, `ruby`, `perl`, `php`, `lua` | Can execute arbitrary code — the binary name tells you nothing about what it runs |

Learned data is stored in `~/.claude/learned-allowlist.json`. You can inspect, edit, or delete entries at any time.

## Install

**One-liner:**

```bash
curl -fsSL https://raw.githubusercontent.com/phspagiari/claude-code-allowlist/main/install.sh | bash
```

**From a clone:**

```bash
git clone https://github.com/phspagiari/claude-code-allowlist.git
cd claude-code-allowlist
./install.sh
```

**What it does:**

1. Copies `allowlist-approve.py` and `allowlist-learn.py` to `~/.claude/hooks/`
2. Adds `PreToolUse` and `PostToolUse` entries to `~/.claude/settings.local.json`
3. If hooks are already configured, skips without duplicating

## Built-in Safe Lists

### Always-safe binaries (auto-approved in compound commands)

<details>
<summary>File reading</summary>

`cat`, `head`, `tail`, `less`, `more`, `bat`, `file`, `stat`, `wc`, `md5`, `md5sum`, `shasum`, `sha256sum`, `sha1sum`, `xxd`, `hexdump`, `strings`, `od`, `readlink`, `realpath`, `dirname`, `basename`

</details>

<details>
<summary>Search and listing</summary>

`find`, `grep`, `egrep`, `fgrep`, `rg`, `ag`, `fd`, `ls`, `tree`, `du`, `df`

</details>

<details>
<summary>Text processing (stdout-only)</summary>

`sort`, `uniq`, `cut`, `tr`, `awk`, `sed`, `jq`, `yq`, `diff`, `comm`, `paste`, `join`, `column`, `fmt`, `fold`, `rev`, `tac`, `nl`, `expand`, `unexpand`, `base64`, `iconv`

Note: `sed -i` and `awk -i inplace` are always blocked even though the binaries themselves are safe.

</details>

<details>
<summary>Output and system info</summary>

`echo`, `printf`, `true`, `false`, `whoami`, `hostname`, `uname`, `date`, `uptime`, `id`, `env`, `printenv`, `pwd`, `type`, `which`, `command`, `ps`

</details>

<details>
<summary>Shell builtins</summary>

`export`, `local`, `declare`, `set`, `test`, `[`, `[[`, `cd`, `pushd`, `popd`

</details>

<details>
<summary>Wrappers and misc</summary>

`xargs`, `time`, `seq`, `sleep`, `wait`, `man`, `info`, `help`, `gh`, `newrelic`, `colima`, `sw_vers`, `sysctl`, `launchctl`

Note: `xargs` with a dangerous binary (e.g., `xargs rm`) is always blocked.

</details>

### Subcommand-checked binaries

These binaries are only auto-approved when followed by a known-safe subcommand:

| Binary | Safe subcommands |
|--------|-----------------|
| `git` | `status`, `log`, `diff`, `show`, `blame`, `branch`, `remote`, `rev-parse`, `stash`, `config`, `shortlog`, `tag`, `describe`, `ls-files`, `ls-tree`, `cat-file`, `rev-list`, `name-rev`, `merge-base`, `reflog`, `grep`, `for-each-ref`, `version`, `help`, `count-objects`, `fsck` |
| `kubectl` | `get`, `describe`, `logs`, `top`, `cluster-info`, `api-resources`, `api-versions`, `explain`, `version`, `auth`, `config`, `diff`, `rollout`, `port-forward` |
| `gcloud` | `list`, `describe`, `info`, `version`, `auth`, `config`, `logging`, `components`, `container` |
| `docker` | `ps`, `images`, `info`, `version`, `inspect`, `logs`, `stats`, `network`, `volume`, `port`, `top`, `diff`, `history` |
| `brew` | `list`, `info`, `search`, `deps`, `log`, `leaves`, `outdated`, `config`, `doctor`, `services` |

When you approve `git push` or `kubectl apply`, the learning hook adds those subcommands to the safe list for future sessions.

## Compound Command Examples

| Command | Extracted | Result |
|---------|-----------|--------|
| `for f in *.go; do grep pattern "$f"; done` | `grep` | Auto-approved |
| `cd /tmp && ls -la && cat README.md` | `cd`, `ls`, `cat` | Auto-approved |
| `kubectl get pods \| grep -v Running \| sort` | `kubectl get`, `grep`, `sort` | Auto-approved |
| `VAR=$(git rev-parse HEAD) && echo $VAR` | `git rev-parse`, `echo` | Auto-approved |
| `find . -name "*.go" \| head -20` | `find`, `head` | Auto-approved |
| `for f in *.log; do rm "$f"; done` | `rm` | **Blocked** |
| `echo data > /tmp/output.txt` | redirect to file | **Blocked** |
| `find . -exec rm {} \;` | `-exec rm` | **Blocked** |
| `sed -i 's/foo/bar/' file.txt` | `sed -i` | **Blocked** |
| `cat file \| tee output.txt` | `tee` | **Blocked** |
| `git push origin main` | `git push` (not in safe subcommands) | **Blocked** |

## Pattern Syntax Reference

The hook supports all `permissions.allow` pattern formats:

| Pattern | What it matches |
|---------|----------------|
| `Read` | All Read tool calls |
| `Bash(git log *)` | Glob match on the full command string |
| `Bash(python3:*)` | Colon syntax — matches any command where the first word is `python3` |
| `mcp__slack__channels_list` | Exact MCP tool name |
| `mcp__bigquery__*` | Glob on MCP tool names |
| `Read(//usr/**)` | Absolute path prefix (`//` = `/`) |
| `Read(~/path/**)` | Home-relative path |
| `WebFetch(domain:github.com)` | URL domain match |
| `Skill(name)` | Specific skill invocation |
| `Agent(type)` | Specific subagent type or name |

## Example Configuration

See [`settings.example.json`](settings.example.json) for a starter set of read-only patterns you can add to your `~/.claude/settings.local.json` under `permissions.allow`.

## Files

| File | Location after install | Purpose |
|------|----------------------|---------|
| `allowlist-approve.py` | `~/.claude/hooks/` | PreToolUse — auto-approves safe calls |
| `allowlist-learn.py` | `~/.claude/hooks/` | PostToolUse — learns from manual approvals |
| `learned-allowlist.json` | `~/.claude/` | Auto-generated — accumulated learned patterns |
| Tracking markers | `/tmp/claude-hook-tracking-<uid>/` | Ephemeral — coordinate between the two hooks |

## Testing

```bash
# Should output JSON with permissionDecision: allow
echo '{"tool_name":"Bash","tool_input":{"command":"git log --oneline"}}' \
  | python3 ~/.claude/hooks/allowlist-approve.py

# Compound command — also approved
echo '{"tool_name":"Bash","tool_input":{"command":"for f in *.go; do grep TODO \"$f\"; done"}}' \
  | python3 ~/.claude/hooks/allowlist-approve.py

# Dangerous — no output (falls through to normal prompt)
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' \
  | python3 ~/.claude/hooks/allowlist-approve.py

# Redirect blocked even though echo is safe
echo '{"tool_name":"Bash","tool_input":{"command":"echo secret > /tmp/leak.txt"}}' \
  | python3 ~/.claude/hooks/allowlist-approve.py
```

## Uninstall

```bash
rm ~/.claude/hooks/allowlist-approve.py ~/.claude/hooks/allowlist-learn.py
rm -f ~/.claude/learned-allowlist.json
rm -rf /tmp/claude-hook-tracking-$(id -u)
```

Then remove the `PreToolUse` and `PostToolUse` hook entries from `~/.claude/settings.local.json`.

## Requirements

- Python 3 (standard library only, no external dependencies)
- Claude Code

## License

MIT
