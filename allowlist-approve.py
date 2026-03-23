#!/usr/bin/env python3
"""Claude Code PreToolUse hook that propagates permissions.allow to subagents.

Claude Code has a known bug where subagents (spawned via the Agent tool) don't
inherit permissions.allow from settings files. This hook reads the allow patterns
from all settings scopes and auto-approves matching tool calls, making permissions
work consistently for both the main session and all subagents.

Settings files read (in order, all patterns merged):
  1. ~/.claude/settings.json          (user shared)
  2. ~/.claude/settings.local.json    (user local)
  3. <cwd>/.claude/settings.json      (project shared)
  4. <cwd>/.claude/settings.local.json (project local)

Supported pattern formats (same as settings.json permissions.allow):
  ToolName              - Allow all uses of this tool
  ToolName(specifier)   - Allow with specific arguments
  Bash(command pattern) - Glob match on bash command (* = any chars)
  Bash(cmd:*)           - Match any command starting with binary "cmd"
  Read(//absolute/**)   - Match absolute file paths (// = /)
  Read(~/path/**)       - Match home-relative paths
  WebFetch(domain:host) - Match specific domains
  mcp__server__tool     - Exact MCP tool name
  mcp__server__*        - Glob match on MCP tool names

Related issues:
  https://github.com/anthropics/claude-code/issues/28584
  https://github.com/anthropics/claude-code/issues/22665
  https://github.com/anthropics/claude-code/issues/18950
  https://github.com/anthropics/claude-code/issues/10906
"""

import sys
import json
import re
import fnmatch
import os

HOME = os.path.expanduser("~")

SETTINGS_FILES = [
    os.path.join(HOME, ".claude", "settings.json"),
    os.path.join(HOME, ".claude", "settings.local.json"),
]


def load_patterns(cwd):
    """Load and merge permissions.allow from all settings files."""
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
                domain = specifier[7:]
                url = tool_input.get("url", "")
                return domain in url
            return False

        if pattern_tool in ("Read", "Edit", "Write"):
            file_path = tool_input.get("file_path", "")
            return path_matches(file_path, specifier)

        if pattern_tool == "Skill":
            skill = tool_input.get("skill", "")
            return fnmatch.fnmatch(skill, specifier)

        if pattern_tool == "Agent":
            agent_type = tool_input.get("subagent_type", "")
            agent_name = tool_input.get("name", "")
            return fnmatch.fnmatch(agent_type, specifier) or fnmatch.fnmatch(
                agent_name, specifier
            )

        return False

    return fnmatch.fnmatch(tool_name, pattern)


def path_matches(file_path, specifier):
    """Match file path against a specifier pattern."""
    specifier = os.path.expanduser(specifier)
    if specifier.startswith("//"):
        specifier = specifier[1:]
    if "**" in specifier:
        prefix = specifier.split("**")[0]
        return file_path.startswith(prefix)
    return fnmatch.fnmatch(file_path, specifier)


def approve(pattern):
    """Output JSON to auto-approve the tool call."""
    json.dump(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "permissionDecisionReason": f"Auto-approved (allowlist-hook): {pattern}",
            }
        },
        sys.stdout,
    )
    sys.exit(0)


def main():
    try:
        input_data = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        sys.exit(0)

    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})
    cwd = input_data.get("cwd", "")

    for pattern in load_patterns(cwd):
        if matches(tool_name, tool_input, pattern):
            approve(pattern)
            return

    sys.exit(0)


if __name__ == "__main__":
    main()
