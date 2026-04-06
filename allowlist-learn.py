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
  MCP / other tools:
    - Learns the exact tool name
  Read / Edit / Write:
    - Learns a path-prefix pattern from the file's project directory
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

# Keep in sync with allowlist-approve.py
SUBCOMMAND_BINARIES = {"git", "kubectl", "gcloud", "docker", "brew", "npm", "cargo", "go"}

INTERPRETERS = {
    "sh", "bash", "zsh", "dash", "fish", "csh", "tcsh",
    "python", "python3", "python2",
    "node", "deno", "bun",
    "ruby", "perl", "php", "lua",
}

DANGEROUS_BINARIES = {
    "rm", "rmdir", "mv", "chmod", "chown", "chgrp",
    "mkfs", "fdisk", "dd", "shred",
    "kill", "killall", "pkill",
    "reboot", "shutdown", "halt", "poweroff",
    "sudo", "su", "doas",
}

SHELL_KEYWORDS = {
    "for", "while", "until", "if", "then", "else", "elif",
    "fi", "do", "done", "case", "esac", "in", "select",
    "function", "time",
}


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

    Splits on separators, skips shell keywords/assignments/flags,
    returns list of (binary_name, [args]) tuples.
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
            results.append((cmd, args[:3]))

    # Also extract from $() substitutions
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
            # Find the subcommand (first non-flag arg)
            subcmd = None
            for a in args:
                if not a.startswith("-"):
                    subcmd = a
                    break
            if subcmd:
                if binary not in learned["safe_subcommands"]:
                    learned["safe_subcommands"][binary] = []
                if subcmd not in learned["safe_subcommands"][binary]:
                    learned["safe_subcommands"][binary].append(subcmd)
                    pattern = f"Bash({binary} {subcmd} *)"
                    if pattern not in learned["patterns"]:
                        learned["patterns"].append(pattern)
                    print(f"[learn] {binary} {subcmd}", file=sys.stderr)
                    changed = True
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
    # For MCP tools, learn exact name
    if tool_name.startswith("mcp__"):
        if tool_name not in learned["safe_tools"]:
            learned["safe_tools"].append(tool_name)
            print(f"[learn] safe tool: {tool_name}", file=sys.stderr)
            return True
        return False

    # For Read/Edit/Write, learn a path pattern
    if tool_name in ("Read", "Edit", "Write"):
        file_path = tool_input.get("file_path", "")
        if not file_path:
            return False
        # Try to find git root for a project-scoped pattern
        prefix = _find_project_root(file_path)
        if prefix:
            pattern = f"{tool_name}(//{prefix}/**)"
            if pattern not in learned["patterns"]:
                learned["patterns"].append(pattern)
                print(f"[learn] {pattern}", file=sys.stderr)
                return True
        return False

    # For other tools, learn exact name
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
