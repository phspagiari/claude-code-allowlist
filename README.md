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
- **Verb-based subcommand checking** — scans all positional (non-flag) args for recognized verbs, so `kubectl -n prod get pods` works even though `get` isn't the first arg

**Safety Veto.** Runs on every Bash approval, even when a Phase 1/2 pattern matches. Always blocks:

- Output redirections to files (`>`, `>>` — but allows `>/dev/null` and `>&2`)
- `sed -i` (in-place file edit)
- `awk -i inplace`
- `tee` (writes to files)
- `find -exec`/`-execdir`/`-ok`/`-okdir` with dangerous binaries
- `xargs` with dangerous binaries
- Unsafe subcommands for checked binaries (e.g., `kubectl delete` even if matched by a broad `Bash(kubectl *)` pattern)

### `allowlist-learn.py` (PostToolUse)

Runs after every tool call. When you manually press "yes" to approve something, this hook extracts patterns and saves them so the same kind of call is auto-approved next time.

**How it knows you pressed "yes":** The PreToolUse hook writes a tracking marker (an md5 hash file in `/tmp/`) when it auto-approves. If PostToolUse runs and finds no marker, it means the user approved manually — time to learn.

**What it learns:**

| Approval | Learned as |
|----------|-----------|
| `bazel build //target:all` | `bazel` as safe binary — matches `bazel test`, `bazel query`, etc. |
| `git stash pop` | `git stash` as safe subcommand (not all of git) |
| `kubectl apply -f manifest.yaml` | `kubectl apply` as safe subcommand |
| `npm run build` | `npm run` as safe subcommand |
| `mcp__custom__my_tool` | Exact MCP tool name |
| `Read(/path/to/project/src/main.go)` | `Read(//path/to/project/**)` (project-root pattern) |
| `WebSearch` | Exact tool name |

Learned subcommands **override built-in unsafe lists** — if you approve `kubectl apply`, the hook trusts that and auto-approves future `kubectl apply` calls.

**What it never learns:**

| Category | Examples | Why |
|----------|----------|-----|
| Dangerous binaries | `rm`, `rmdir`, `mv`, `chmod`, `chown`, `dd`, `shred`, `truncate`, `kill`, `sudo`, `su` | Destructive or privilege-escalating |
| Interpreters | `sh`, `bash`, `zsh`, `python`, `python3`, `node`, `deno`, `bun`, `ruby`, `perl`, `npx`, `java` | Can execute arbitrary code — the binary name tells you nothing about what it runs |
| Broad tools | `Agent`, `Write`, `Edit`, `NotebookEdit`, `WebFetch` | One specific approval shouldn't grant blanket access |

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
<summary>Compilers</summary>

`rustc`, `gcc`, `g++`, `clang`, `clang++`, `javac`, `tsc`

These compile but don't execute arbitrary code.

</details>

<details>
<summary>Wrappers and misc</summary>

`xargs`, `time`, `seq`, `sleep`, `wait`, `man`, `info`, `help`, `sw_vers`, `sysctl`, `ideviceinfo`, `ideviceinstaller`, `idevicediagnostics`

Note: `xargs` with a dangerous binary (e.g., `xargs rm`) is always blocked.

</details>

### Subcommand-checked binaries

These binaries use **verb-based checking** — the hook scans all positional (non-flag) args for a recognized safe verb. This means `kubectl -n prod get pods` is approved because `get` is found regardless of position.

Unsafe verbs provide conflict resolution: if both a safe and unsafe verb appear (e.g., `kubectl -n get delete pod`), the unsafe verb wins — unless it was previously learned via manual approval.

<details>
<summary>git — 34 safe verbs</summary>

**Safe:** `status`, `log`, `diff`, `show`, `blame`, `branch`, `remote`, `rev-parse`, `stash`, `config`, `shortlog`, `tag`, `describe`, `ls-files`, `ls-tree`, `cat-file`, `rev-list`, `name-rev`, `merge-base`, `reflog`, `grep`, `for-each-ref`, `version`, `help`, `count-objects`, `fsck`, `whatchanged`, `cherry`, `range-diff`, `var`, `fetch`, `archive`, `bundle`, `notes`, `bugreport`, `diagnose`, `submodule`, `worktree`

**Unsafe (always prompt):** `push`, `reset`, `clean`, `rm`, `filter-branch`, `checkout`, `switch`, `restore`

</details>

<details>
<summary>kubectl — 18 safe verbs</summary>

**Safe:** `get`, `describe`, `logs`, `top`, `cluster-info`, `api-resources`, `api-versions`, `explain`, `version`, `auth`, `config`, `diff`, `port-forward`, `events`, `wait`, `completion`, `options`, `plugin`, `rollout`

**Unsafe (always prompt):** `delete`, `exec`, `run`, `drain`, `cp`, `attach`

</details>

<details>
<summary>gcloud — verb-level, works at any depth</summary>

**Safe:** `list`, `describe`, `get`, `get-credentials`, `read`, `info`, `version`, `print-access-token`, `print-identity-token`, `export`

**Unsafe (always prompt):** `delete`, `ssh`, `scp`, `deploy`, `create`, `update`

Works for `gcloud compute instances list`, `gcloud container clusters describe my-cluster`, etc.

</details>

<details>
<summary>docker — verb-level</summary>

**Safe:** `ps`, `images`, `info`, `version`, `inspect`, `logs`, `stats`, `port`, `top`, `diff`, `history`, `events`, `wait`, `search`, `ls`

**Unsafe (always prompt):** `rm`, `rmi`, `kill`, `stop`, `run`, `exec`, `build`, `push`, `prune`, `load`, `import`

Works for both `docker ps` and `docker container ls`.

</details>

<details>
<summary>brew — 16 safe verbs</summary>

**Safe:** `list`, `info`, `search`, `deps`, `log`, `leaves`, `outdated`, `config`, `doctor`, `desc`, `cat`, `formulae`, `casks`, `commands`, `home`, `uses`

**Unsafe (always prompt):** `install`, `uninstall`, `remove`, `upgrade`, `reinstall`, `link`, `unlink`, `cleanup`, `autoremove`

</details>

<details>
<summary>npm — 23 safe verbs</summary>

**Safe:** `list`, `ls`, `info`, `view`, `show`, `outdated`, `explain`, `why`, `doctor`, `version`, `help`, `search`, `audit`, `fund`, `pack`, `prefix`, `root`, `bin`, `bugs`, `docs`, `home`, `repo`, `completion`, `access`

**Unsafe (always prompt):** `install`, `uninstall`, `update`, `run`, `exec`, `start`, `test`, `publish`, `unpublish`, `link`, `ci`

</details>

<details>
<summary>go — 7 safe verbs</summary>

**Safe:** `version`, `env`, `list`, `doc`, `help`, `vet`, `tool`

**Unsafe (always prompt):** `run`, `build`, `install`, `get`, `generate`, `test`, `clean`

</details>

<details>
<summary>cargo — 14 safe verbs</summary>

**Safe:** `check`, `clippy`, `doc`, `metadata`, `tree`, `search`, `version`, `help`, `audit`, `outdated`, `verify-project`, `read-manifest`, `pkgid`, `locate-project`

**Unsafe (always prompt):** `build`, `run`, `install`, `test`, `bench`, `publish`, `clean`, `update`, `fix`

</details>

<details>
<summary>helm — 14 safe verbs</summary>

**Safe:** `list`, `get`, `status`, `show`, `history`, `template`, `lint`, `search`, `repo`, `env`, `version`, `help`, `completion`, `plugin`

**Unsafe (always prompt):** `install`, `upgrade`, `uninstall`, `delete`, `rollback`, `push`, `pull`

</details>

<details>
<summary>terraform — 10 safe verbs</summary>

**Safe:** `version`, `validate`, `plan`, `output`, `show`, `graph`, `providers`, `state`, `workspace`, `fmt`

**Unsafe (always prompt):** `apply`, `destroy`, `import`, `taint`, `untaint`, `init`

</details>

<details>
<summary>gh (GitHub CLI) — verb-level</summary>

**Safe:** `list`, `view`, `status`, `checks`, `diff`, `watch`, `browse`, `search`

**Unsafe (always prompt):** `create`, `close`, `merge`, `comment`, `delete`, `fork`, `cancel`, `rerun`, `edit`, `add`, `remove`, `archive`, `transfer`

Works for `gh pr list`, `gh issue view 123`, etc.

</details>

<details>
<summary>newrelic, launchctl, colima</summary>

**newrelic safe:** `query`, `search`, `list`, `describe`, `get`

**launchctl safe:** `list`, `print`, `blame`, `dumpstate`, `managerpid`, `manageruid`, `managername`, `error`, `variant`, `version`
**launchctl unsafe:** `load`, `unload`, `start`, `stop`, `enable`, `disable`, `bootstrap`, `bootout`, `kickstart`, `kill`, `submit`, `remove`

**colima safe:** `status`, `list`, `version`
**colima unsafe:** `start`, `stop`, `delete`, `restart`, `ssh`

</details>

### Interpreters (flag-only mode)

These are in the subcommand-checked list with **empty safe sets** — meaning only bare or flag-only invocations are approved:

| Command | Result |
|---------|--------|
| `node --version` | Approved (no positional args) |
| `python3 -V` | Approved (no positional args) |
| `java --version` | Approved (no positional args) |
| `deno lint src/` | Approved (`lint` is a safe deno verb) |
| `node script.js` | **Blocked** (positional arg, no safe verb) |
| `python3 script.py` | **Blocked** |
| `npx create-react-app` | **Blocked** |
| `java -jar app.jar` | **Blocked** |

Applies to: `node`, `python`, `python3`, `python2`, `ruby`, `perl`, `java`, `npx`, `deno`, `bun`

`deno` has a few safe verbs: `check`, `lint`, `info`, `doc`, `types`, `completions`

## Compound Command Examples

| Command | What happens | Result |
|---------|-------------|--------|
| `for f in *.go; do grep pattern "$f"; done` | Extracts `grep` | Auto-approved |
| `cd /tmp && ls -la && cat README.md` | Extracts `cd`, `ls`, `cat` | Auto-approved |
| `kubectl -n prod get pods \| grep -v Running \| sort` | Extracts `kubectl get`, `grep`, `sort` | Auto-approved |
| `VAR=$(git rev-parse HEAD) && echo $VAR` | Recurses into `$()`, extracts `git rev-parse`, `echo` | Auto-approved |
| `find . -name "*.go" \| head -20` | Extracts `find`, `head` | Auto-approved |
| `node --version && npm list` | `node` flag-only OK, `npm list` safe verb | Auto-approved |
| `for f in *.log; do rm "$f"; done` | Extracts `rm` (dangerous) | **Blocked** |
| `echo data > /tmp/output.txt` | Redirect to file detected | **Blocked** |
| `find . -exec rm {} \;` | `-exec rm` detected | **Blocked** |
| `find . -ok rm {} \;` | `-ok rm` detected | **Blocked** |
| `sed -i 's/foo/bar/' file.txt` | `sed -i` detected | **Blocked** |
| `cat file \| tee output.txt` | `tee` detected | **Blocked** |
| `git push origin main` | `push` is unsafe git verb | **Blocked** |
| `kubectl -n get delete pod` | `delete` is unsafe, overrides `get` | **Blocked** |

## MCP Tool Learning

When you approve an MCP tool call, the learning hook saves the **exact tool name**:

```
You approve: mcp__bigquery__execute_sql
Learned:     mcp__bigquery__execute_sql (exact match)
Result:      All future mcp__bigquery__execute_sql calls auto-approved
             mcp__bigquery__get_table_info still prompts (different tool)
```

This works for any MCP server — observability, Slack, incident.io, ArgoCD, etc.

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
| Tracking markers | `/tmp/claude-hook-tracking-<uid>/` | Ephemeral — coordinate between the two hooks (auto-cleaned) |

## Testing

```bash
# Should output JSON with permissionDecision: allow
echo '{"tool_name":"Bash","tool_input":{"command":"git log --oneline"}}' \
  | python3 ~/.claude/hooks/allowlist-approve.py

# Compound command — also approved
echo '{"tool_name":"Bash","tool_input":{"command":"for f in *.go; do grep TODO \"$f\"; done"}}' \
  | python3 ~/.claude/hooks/allowlist-approve.py

# Verb-position-independent kubectl
echo '{"tool_name":"Bash","tool_input":{"command":"kubectl -n prod get pods"}}' \
  | python3 ~/.claude/hooks/allowlist-approve.py

# Interpreter flag-only
echo '{"tool_name":"Bash","tool_input":{"command":"node --version"}}' \
  | python3 ~/.claude/hooks/allowlist-approve.py

# Dangerous — no output (falls through to normal prompt)
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' \
  | python3 ~/.claude/hooks/allowlist-approve.py

# Redirect blocked even though echo is safe
echo '{"tool_name":"Bash","tool_input":{"command":"echo secret > /tmp/leak.txt"}}' \
  | python3 ~/.claude/hooks/allowlist-approve.py

# Unsafe verb blocked even in simple command
echo '{"tool_name":"Bash","tool_input":{"command":"kubectl delete pod my-pod"}}' \
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
