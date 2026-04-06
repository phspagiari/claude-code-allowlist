#!/usr/bin/env python3
"""Claude Code PreToolUse hook — auto-approves safe tool calls.

Three-phase matching:
  1. Static patterns from settings.json permissions.allow
  2. Learned patterns from ~/.claude/learned-allowlist.json
  3. Compound command safety analysis (Bash only) — decomposes
     for/while/if, pipelines, &&/||/; chains and checks every
     sub-command against a safe-binaries list.

When auto-approving, writes a tracking marker so the PostToolUse
learning hook knows this was NOT a manual user approval.
"""

import sys
import json
import re
import fnmatch
import os
import hashlib

HOME = os.path.expanduser("~")
TRACKING_DIR = f"/tmp/claude-hook-tracking-{os.getuid()}"
LEARNED_FILE = os.path.join(HOME, ".claude", "learned-allowlist.json")

SETTINGS_FILES = [
    os.path.join(HOME, ".claude", "settings.json"),
    os.path.join(HOME, ".claude", "settings.local.json"),
]

# ── Always-safe binaries (read-only / no side-effects) ──────────────

SAFE_BINARIES = {
    # File reading
    "cat", "head", "tail", "less", "more", "bat", "file", "stat", "wc",
    "md5", "md5sum", "shasum", "sha256sum", "sha1sum",
    "xxd", "hexdump", "strings", "od",
    "readlink", "realpath", "dirname", "basename",
    # Search & listing
    "find", "grep", "egrep", "fgrep", "rg", "ag", "fd",
    "ls", "tree", "du", "df",
    # Text processing (stdout-only, no -i)
    "sort", "uniq", "cut", "tr", "awk", "sed", "jq", "yq",
    "diff", "comm", "paste", "join", "column", "fmt", "fold",
    "rev", "tac", "nl", "expand", "unexpand", "base64", "iconv",
    # Output
    "echo", "printf", "true", "false",
    # System info
    "whoami", "hostname", "uname", "date", "uptime", "id",
    "env", "printenv", "pwd", "type", "which", "command",
    "ps",
    # Shell builtins / flow (safe)
    "export", "local", "declare", "set", "test", "[", "[[",
    "cd", "pushd", "popd",
    # Version / info
    "node", "npm", "npx", "go", "python", "python3",
    "java", "rustc", "cargo", "ruby", "perl",
    "man", "info", "help",
    # Safe wrappers
    "xargs", "time", "seq", "sleep", "wait",
    # macOS / misc
    "ideviceinfo", "ideviceinstaller", "idevicediagnostics",
    "colima", "sw_vers", "sysctl", "launchctl",
    "newrelic", "gh",
}

# Binaries that need subcommand validation
SUBCOMMAND_SAFE = {
    "git": {
        "status", "log", "diff", "show", "blame", "branch", "remote",
        "rev-parse", "stash", "config", "shortlog", "tag", "describe",
        "ls-files", "ls-tree", "cat-file", "rev-list", "name-rev",
        "merge-base", "reflog", "grep", "for-each-ref", "version",
        "help", "count-objects", "fsck",
    },
    "kubectl": {
        "get", "describe", "logs", "top", "cluster-info", "api-resources",
        "api-versions", "explain", "version", "auth", "config", "diff",
        "rollout", "port-forward",
    },
    "gcloud": {
        "list", "describe", "info", "version", "auth", "config",
        "logging", "components", "container",
    },
    "docker": {
        "ps", "images", "info", "version", "inspect", "logs",
        "stats", "network", "volume", "port", "top", "diff", "history",
    },
    "brew": {
        "list", "info", "search", "deps", "log", "leaves", "outdated",
        "config", "doctor", "services",
    },
}

# Never auto-approve these
DANGEROUS_BINARIES = {
    "rm", "rmdir", "mv", "chmod", "chown", "chgrp",
    "mkfs", "fdisk", "dd", "shred",
    "kill", "killall", "pkill",
    "reboot", "shutdown", "halt", "poweroff",
    "sudo", "su", "doas",
}

# Interpreters — can run arbitrary code, never learn as "safe binary"
INTERPRETERS = {
    "sh", "bash", "zsh", "dash", "fish", "csh", "tcsh",
    "python", "python3", "python2",
    "node", "deno", "bun",
    "ruby", "perl", "php", "lua",
}

# Shell keywords — not binaries, skip during extraction
SHELL_KEYWORDS = {
    "for", "while", "until", "if", "then", "else", "elif",
    "fi", "do", "done", "case", "esac", "in", "select",
    "function", "time",
}


# ── Pattern loading ─────────────────────────────────────────────────

def load_patterns(cwd):
    """Merge permissions.allow from all settings files."""
    files = list(SETTINGS_FILES)
    if cwd:
        files.append(os.path.join(cwd, ".claude", "settings.json"))
        files.append(os.path.join(cwd, ".claude", "settings.local.json"))

    patterns = []
    seen = set()
    for path in files:
        if not os.path.exists(path):
            continue
        try:
            with open(path) as f:
                data = json.load(f)
            for p in data.get("permissions", {}).get("allow", []):
                if p not in seen:
                    seen.add(p)
                    patterns.append(p)
        except (json.JSONDecodeError, OSError):
            continue
    return patterns


def load_learned():
    """Load learned patterns from previous user approvals."""
    default = {"patterns": [], "safe_binaries": {}, "safe_subcommands": {}, "safe_tools": []}
    if not os.path.exists(LEARNED_FILE):
        return default
    try:
        with open(LEARNED_FILE) as f:
            data = json.load(f)
        for k in default:
            data.setdefault(k, default[k])
        return data
    except (json.JSONDecodeError, OSError):
        return default


# ── Pattern matching (original behaviour, kept intact) ──────────────

def matches(tool_name, tool_input, pattern):
    """Check if a tool call matches an allowlist pattern."""
    m = re.match(r"^([\w-]+)\((.+)\)$", pattern)
    if m:
        pattern_tool, specifier = m.groups()
        if tool_name != pattern_tool:
            return False

        if pattern_tool == "Bash":
            command = tool_input.get("command", "")
            if not command:
                return False
            if ":" in specifier and not specifier.startswith("/"):
                cmd_name = specifier.split(":", 1)[0]
                words = command.split()
                return bool(words) and words[0] == cmd_name
            return fnmatch.fnmatch(command, specifier)

        if pattern_tool == "WebFetch":
            if specifier.startswith("domain:"):
                return specifier[7:] in tool_input.get("url", "")
            return False

        if pattern_tool in ("Read", "Edit", "Write"):
            return path_matches(tool_input.get("file_path", ""), specifier)

        if pattern_tool == "Skill":
            return fnmatch.fnmatch(tool_input.get("skill", ""), specifier)

        if pattern_tool == "Agent":
            at = tool_input.get("subagent_type", "")
            an = tool_input.get("name", "")
            return fnmatch.fnmatch(at, specifier) or fnmatch.fnmatch(an, specifier)

        return False

    # No parentheses → exact or glob on tool name
    return fnmatch.fnmatch(tool_name, pattern)


def path_matches(file_path, specifier):
    specifier = os.path.expanduser(specifier)
    if specifier.startswith("//"):
        specifier = specifier[1:]
    if "**" in specifier:
        return file_path.startswith(specifier.split("**")[0])
    return fnmatch.fnmatch(file_path, specifier)


# ── Compound-command safety analysis ────────────────────────────────

def remove_quoted(s):
    """Strip quoted content to avoid matching operators inside quotes."""
    result, i = [], 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            i += 2
            continue
        if c == '"':
            i += 1
            while i < len(s) and s[i] != '"':
                if s[i] == "\\":
                    i += 1
                i += 1
            i += 1
            result.append('""')
            continue
        if c == "'":
            i += 1
            while i < len(s) and s[i] != "'":
                i += 1
            i += 1
            result.append("''")
            continue
        result.append(c)
        i += 1
    return "".join(result)


def is_compound(command):
    """Check if command contains pipes, semicolons, or compound operators."""
    cleaned = remove_quoted(command)
    return bool(re.search(r"[|;]|&&", cleaned))


def find_potential_binaries(command):
    """Extract (binary, args) tuples from a potentially compound command.

    Strategy: tokenize, then walk tokens tracking "command position" —
    a position where the next non-flag, non-keyword word is a binary.
    Skips for/while/until/case header segments (the body after 'do'
    will appear as its own segment after splitting on ';').
    """
    cleaned = remove_quoted(command)

    # Extract and recurse into $() command substitutions
    binaries = []
    for sub in re.findall(r"\$\(([^)]+)\)", cleaned):
        binaries.extend(find_potential_binaries(sub))
    # Remove $() so we don't re-process
    cleaned = re.sub(r"\$\([^)]*\)", " __SUB__ ", cleaned)

    # Split on command separators (order matters: && || before | ;)
    segments = re.split(r"\s*(?:&&|\|\|)\s*|\s*[;|]\s*", cleaned)

    for seg in segments:
        seg = seg.strip()
        if not seg:
            continue
        words = seg.split()
        if not words:
            continue

        first = words[0].strip("(){}$`")

        # Skip loop/conditional HEADER segments — the body commands
        # appear after 'do'/'then' in separate segments after splitting on ';'
        if first in ("for", "while", "until", "case"):
            continue

        cmd = None
        args = []
        for w in words:
            w = w.strip("(){}$`")
            if not w or w == "__SUB__":
                continue
            if w in SHELL_KEYWORDS:
                # After a keyword like 'do'/'then', next word is a command
                cmd = None
                continue
            if re.match(r"^\w+=", w):
                # Variable assignment — next word may be a command
                continue
            if cmd is None and not w.startswith("-"):
                cmd = os.path.basename(w)
                args = []
            elif cmd is not None:
                args.append(w)
        if cmd and not re.match(r"^\d+$", cmd):
            binaries.append((cmd, args[:5]))

    return binaries


def has_dangerous_redirects(command):
    """Detect output redirections to files (not /dev/null or fd dupes)."""
    cleaned = remove_quoted(command)
    for target in re.findall(r"\d*>{1,2}\s*(&?\S+)", cleaned):
        target = target.strip()
        if target in ("/dev/null", "&1", "&2"):
            continue
        return True
    return False


def has_dangerous_flags(command):
    """Detect known-dangerous flag combos that make safe binaries unsafe."""
    cleaned = remove_quoted(command)
    # sed -i (in-place edit)
    if re.search(r"\bsed\b[^|;]*\s+-i", cleaned):
        return True, "sed -i (in-place edit)"
    # awk -i inplace
    if re.search(r"\bawk\b[^|;]*\s+-i\s*inplace", cleaned):
        return True, "awk -i inplace"
    # tee writes to files
    if re.search(r"\btee\b", cleaned):
        return True, "tee (writes to files)"
    # find -exec/-execdir with dangerous binary
    for m in re.finditer(r"-(?:exec|execdir)\s+(\S+)", cleaned):
        if os.path.basename(m.group(1)) in DANGEROUS_BINARIES:
            return True, f"-exec {m.group(1)}"
    # xargs with dangerous binary
    m = re.search(r"\bxargs\s+(?:-\S+\s+)*(\S+)", cleaned)
    if m and os.path.basename(m.group(1)) in DANGEROUS_BINARIES:
        return True, f"xargs {m.group(1)}"
    return False, ""


def is_safe_command(command, learned):
    """Analyse a Bash command. Returns (safe: bool, reason: str)."""
    if has_dangerous_redirects(command):
        return False, "output redirection to file"

    dangerous, reason = has_dangerous_flags(command)
    if dangerous:
        return False, reason

    binaries = find_potential_binaries(command)
    if not binaries:
        return False, "could not parse any commands"

    learned_bins = set(learned.get("safe_binaries", {}).keys())
    learned_subcmds = learned.get("safe_subcommands", {})
    all_safe = SAFE_BINARIES | learned_bins

    for binary, args in binaries:
        if binary in DANGEROUS_BINARIES:
            return False, f"dangerous binary: {binary}"

        # xargs: also check the command it runs
        if binary == "xargs" and args:
            inner = os.path.basename(args[0])
            if inner in DANGEROUS_BINARIES:
                return False, f"xargs runs dangerous: {inner}"

        # find -exec: check the command it runs
        if binary == "find":
            for i, a in enumerate(args):
                if a in ("-exec", "-execdir") and i + 1 < len(args):
                    inner = os.path.basename(args[i + 1])
                    if inner in DANGEROUS_BINARIES:
                        return False, f"find -exec runs dangerous: {inner}"

        # Subcommand-checked binaries
        if binary in SUBCOMMAND_SAFE:
            # Find first non-flag arg (the subcommand)
            subcmd = None
            for a in args:
                if not a.startswith("-"):
                    subcmd = a
                    break
            if subcmd is None:
                continue  # No subcommand (e.g. bare "git") — allow, it'll just print help
            builtin_ok = SUBCOMMAND_SAFE[binary]
            learned_ok = set(learned_subcmds.get(binary, []))
            if subcmd not in builtin_ok and subcmd not in learned_ok:
                return False, f"{binary} {subcmd} not in safe list"
            continue

        # Regular binary check
        if binary not in all_safe:
            return False, f"unknown binary: {binary}"

    return True, "all sub-commands safe"


# ── Safety veto (guards pattern matches against compound abuse) ─────

def _bash_safety_veto(tool_name, tool_input, learned):
    """Return True if a Bash pattern match should be VETOED for safety.

    Always blocks redirects and dangerous flags (sed -i, tee).
    For compound commands (pipes, ;, &&) also runs full analysis.
    Non-Bash tools are never vetoed.
    """
    if tool_name != "Bash":
        return False
    command = tool_input.get("command", "")
    if not command:
        return False

    # Quick gates — always check, even for simple commands
    if has_dangerous_redirects(command):
        return True
    dangerous, _ = has_dangerous_flags(command)
    if dangerous:
        return True

    # For compound commands, full safety analysis
    if is_compound(command):
        safe, _ = is_safe_command(command, learned)
        if not safe:
            return True

    return False


# ── Tracking (for learning hook coordination) ──────────────────────

def write_tracking(tool_name, tool_input):
    """Mark this call as auto-approved so PostToolUse knows."""
    os.makedirs(TRACKING_DIR, exist_ok=True)
    sig = json.dumps({"t": tool_name, "i": tool_input}, sort_keys=True)
    h = hashlib.md5(sig.encode()).hexdigest()
    try:
        with open(os.path.join(TRACKING_DIR, h), "w") as f:
            f.write("1")
    except OSError:
        pass
    # Garbage-collect markers older than 1 hour
    try:
        import time
        now = time.time()
        for name in os.listdir(TRACKING_DIR):
            p = os.path.join(TRACKING_DIR, name)
            if now - os.path.getmtime(p) > 3600:
                os.remove(p)
    except OSError:
        pass


# ── Output ──────────────────────────────────────────────────────────

def approve(reason, source="allowlist"):
    json.dump(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "permissionDecisionReason": f"Auto-approved ({source}): {reason}",
            }
        },
        sys.stdout,
    )
    sys.exit(0)


# ── Main ────────────────────────────────────────────────────────────

def main():
    try:
        input_data = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        sys.exit(0)

    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})
    cwd = input_data.get("cwd", "")

    learned = load_learned()

    # Phase 1 — static patterns from settings files
    for pattern in load_patterns(cwd):
        if matches(tool_name, tool_input, pattern):
            if not _bash_safety_veto(tool_name, tool_input, learned):
                write_tracking(tool_name, tool_input)
                approve(pattern, "settings")
            break  # Pattern matched but vetoed — fall through to prompt

    # Phase 2 — learned patterns
    for pattern in learned.get("patterns", []):
        if matches(tool_name, tool_input, pattern):
            if not _bash_safety_veto(tool_name, tool_input, learned):
                write_tracking(tool_name, tool_input)
                approve(pattern, "learned")
            break

    if tool_name in learned.get("safe_tools", []):
        write_tracking(tool_name, tool_input)
        approve(tool_name, "learned-tool")

    # Phase 3 — compound command safety analysis (Bash only)
    if tool_name == "Bash":
        command = tool_input.get("command", "")
        if command:
            safe, reason = is_safe_command(command, learned)
            if safe:
                write_tracking(tool_name, tool_input)
                approve(reason, "safe-analysis")

    # No match — fall through to normal permission prompt
    sys.exit(0)


if __name__ == "__main__":
    main()
