#!/usr/bin/env python3
"""Claude Code PostToolUse hook — learns from manual user approvals.

When the user presses "yes" to approve a tool call that wasn't
auto-approved by the PreToolUse hook, this hook extracts patterns
and saves them to ~/.claude/learned-allowlist.json so that similar
calls are auto-approved next time.

Learning strategy:
  Bash commands:
    - Extracts binary names from the command
    - For subcommand tools (git, kubectl, etc.) learns binary+subcommand
    - For regular tools learns the binary as safe
    - Never learns interpreters (sh, python3, etc.) as safe binaries
    - Never learns dangerous binaries (rm, mv, etc.)
    - Skips loop headers to avoid learning loop variables as binaries
  MCP tools:
    - Learns the exact tool name
  Read:
    - Learns a path-prefix pattern from the file's project directory
  Edit / Write / Agent / WebFetch:
    - NOT learned (too broad — one approval shouldn't grant blanket access)
"""

import sys
import json
import re
import os
import hashlib
from datetime import datetime

HOME = os.path.expanduser("~")
TRACKING_DIR = f"/tmp/claude-hook-tracking-{os.getuid()}"
LEARNED_FILE = os.path.join(HOME, ".claude", "learned-allowlist.json")

# Keep in sync with SUBCOMMAND_SAFE keys in allowlist-approve.py
# (excluding interpreters — those are caught by INTERPRETERS below)
SUBCOMMAND_BINARIES = {
    "git", "kubectl", "gcloud", "docker", "brew", "npm", "go", "cargo",
    "helm", "terraform", "gh", "newrelic", "launchctl", "colima",
}

INTERPRETERS = {
    "sh", "bash", "zsh", "dash", "fish", "csh", "tcsh",
    "python", "python3", "python2",
    "node", "deno", "bun",
    "ruby", "perl", "php", "lua",
    "npx", "java",
}

DANGEROUS_BINARIES = {
    "rm", "rmdir", "mv", "chmod", "chown", "chgrp",
    "mkfs", "fdisk", "dd", "shred", "truncate",
    "kill", "killall", "pkill",
    "reboot", "shutdown", "halt", "poweroff",
    "sudo", "su", "doas",
}

SHELL_KEYWORDS = {
    "for", "while", "until", "if", "then", "else", "elif",
    "fi", "do", "done", "case", "esac", "in", "select",
    "function", "time",
}

# Tools that should never be globally learned
# (one approval of a specific invocation != blanket trust)
TOOL_NEVER_LEARN = {"Agent", "Write", "Edit", "NotebookEdit", "WebFetch"}


def was_auto_approved(tool_name, tool_input):
    """Check and consume the tracking marker left by PreToolUse."""
    sig = json.dumps({"t": tool_name, "i": tool_input}, sort_keys=True)
    h = hashlib.md5(sig.encode()).hexdigest()
    path = os.path.join(TRACKING_DIR, h)
    if os.path.exists(path):
        try:
            os.remove(path)
        except OSError:
            pass
        return True
    return False


def load_learned():
    default = {
        "patterns": [],
        "safe_binaries": {},
        "safe_subcommands": {},
        "safe_tools": [],
    }
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


def save_learned(data):
    os.makedirs(os.path.dirname(LEARNED_FILE), exist_ok=True)
    tmp = LEARNED_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, LEARNED_FILE)


def extract_binaries_simple(command):
    """Lightweight binary extraction for learning.

    Splits on separators, skips shell keywords/assignments/flags
    and loop headers, returns list of (binary_name, [args]) tuples.
    """
    # Remove quoted strings
    cleaned = re.sub(r'"[^"]*"', '""', command)
    cleaned = re.sub(r"'[^']*'", "''", cleaned)
    # Remove $() contents (we'll process originals separately)
    cleaned = re.sub(r"\$\([^)]*\)", " ", cleaned)

    segments = re.split(r"\s*(?:&&|\|\|)\s*|\s*[;|]\s*", cleaned)
    results = []

    for seg in segments:
        words = seg.strip().split()
        if not words:
            continue

        first = words[0].strip("(){}$`")

        # Skip loop/conditional headers (avoids learning loop variables)
        if first in ("for", "while", "until", "case"):
            continue

        cmd = None
        args = []
        for w in words:
            w = w.strip("(){}$`")
            if not w:
                continue
            if w in SHELL_KEYWORDS:
                cmd = None
                continue
            if re.match(r"^\w+=", w):
                continue
            if cmd is None and not w.startswith("-"):
                cmd = os.path.basename(w)
                args = []
            elif cmd is not None:
                args.append(w)
        if cmd and not re.match(r"^\d+$", cmd):
            results.append((cmd, args[:5]))

    # Also extract from $() substitutions in the original command
    for sub in re.findall(r"\$\(([^)]+)\)", command):
        results.extend(extract_binaries_simple(sub))

    return results


def learn_from_bash(command, learned):
    """Learn safe binaries/subcommands from an approved Bash command."""
    now = datetime.now().isoformat()
    changed = False

    binaries = extract_binaries_simple(command)

    for binary, args in binaries:
        # Never learn dangerous or interpreter binaries
        if binary in DANGEROUS_BINARIES or binary in INTERPRETERS:
            continue
        # Skip shell keywords that slipped through
        if binary in SHELL_KEYWORDS:
            continue

        if binary in SUBCOMMAND_BINARIES:
            # Find the verb among positional (non-flag) args
            non_flag_args = [a for a in args if not a.startswith("-")]
            for subcmd in non_flag_args:
                # Only learn the first plausible verb (skip resource names etc.)
                # A verb is typically a short lowercase word
                if len(subcmd) > 30 or "/" in subcmd or "." in subcmd:
                    continue
                if binary not in learned["safe_subcommands"]:
                    learned["safe_subcommands"][binary] = []
                if subcmd not in learned["safe_subcommands"][binary]:
                    learned["safe_subcommands"][binary].append(subcmd)
                    pattern = f"Bash({binary} {subcmd} *)"
                    if pattern not in learned["patterns"]:
                        learned["patterns"].append(pattern)
                    print(f"[learn] {binary} {subcmd}", file=sys.stderr)
                    changed = True
                break  # Only learn the first verb-like arg
        else:
            # Learn binary as safe
            if binary not in learned["safe_binaries"]:
                learned["safe_binaries"][binary] = {
                    "learned_at": now,
                    "example": command[:120],
                }
                pattern = f"Bash({binary} *)"
                if pattern not in learned["patterns"]:
                    learned["patterns"].append(pattern)
                print(f"[learn] safe binary: {binary}", file=sys.stderr)
                changed = True

    return changed


def learn_from_tool(tool_name, tool_input, learned):
    """Learn that a non-Bash tool is safe to auto-approve."""
    # Never globally learn these tools
    if tool_name in TOOL_NEVER_LEARN:
        return False

    # MCP tools — learn exact tool name
    if tool_name.startswith("mcp__"):
        if tool_name not in learned["safe_tools"]:
            learned["safe_tools"].append(tool_name)
            print(f"[learn] safe tool: {tool_name}", file=sys.stderr)
            return True
        return False

    # Read — learn project-scoped path pattern
    if tool_name == "Read":
        file_path = tool_input.get("file_path", "")
        if not file_path:
            return False
        prefix = _find_project_root(file_path)
        if prefix:
            pattern = f"Read(//{prefix}/**)"
            if pattern not in learned["patterns"]:
                learned["patterns"].append(pattern)
                print(f"[learn] {pattern}", file=sys.stderr)
                return True
        return False

    # Other safe tools (Skill, WebSearch, etc.) — learn exact name
    if tool_name not in learned["safe_tools"]:
        learned["safe_tools"].append(tool_name)
        print(f"[learn] safe tool: {tool_name}", file=sys.stderr)
        return True
    return False


def _find_project_root(file_path):
    """Walk up from file_path looking for a .git directory.
    Returns the project root path or None."""
    d = os.path.dirname(file_path)
    for _ in range(20):  # max depth
        if os.path.isdir(os.path.join(d, ".git")):
            return d.lstrip("/")
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    return None


def main():
    try:
        input_data = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        sys.exit(0)

    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})

    # If PreToolUse already auto-approved, nothing to learn
    if was_auto_approved(tool_name, tool_input):
        sys.exit(0)

    # User manually approved — learn from it
    learned = load_learned()
    changed = False

    if tool_name == "Bash":
        command = tool_input.get("command", "")
        if command:
            changed = learn_from_bash(command, learned)
    else:
        changed = learn_from_tool(tool_name, tool_input, learned)

    if changed:
        save_learned(learned)

    sys.exit(0)


if __name__ == "__main__":
    main()
