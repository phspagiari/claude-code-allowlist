#!/bin/bash
# install.sh — Install the claude-code-allowlist hook
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/phspagiari/claude-code-allowlist/main/install.sh | bash
#
# Or from a local clone:
#   ./install.sh

set -euo pipefail

HOOKS_DIR="$HOME/.claude/hooks"
SETTINGS_LOCAL="$HOME/.claude/settings.local.json"
SCRIPT_NAME="allowlist-approve.py"
REPO_RAW="https://raw.githubusercontent.com/phspagiari/claude-code-allowlist/main"

echo "==> Installing claude-code-allowlist hook..."

# 1. Create hooks directory
mkdir -p "$HOOKS_DIR"

# 2. Download or copy the hook script
if [[ -f "$(dirname "$0")/$SCRIPT_NAME" ]] && [[ "$(dirname "$0")" != "." || -f "./$SCRIPT_NAME" ]]; then
    # Local install from cloned repo
    SCRIPT_SOURCE="$(cd "$(dirname "$0")" && pwd)/$SCRIPT_NAME"
    cp "$SCRIPT_SOURCE" "$HOOKS_DIR/$SCRIPT_NAME"
    echo "    Copied from local: $SCRIPT_SOURCE"
else
    # Remote install via curl
    curl -fsSL "$REPO_RAW/$SCRIPT_NAME" -o "$HOOKS_DIR/$SCRIPT_NAME"
    echo "    Downloaded from: $REPO_RAW/$SCRIPT_NAME"
fi

chmod +x "$HOOKS_DIR/$SCRIPT_NAME"
echo "    Installed to: $HOOKS_DIR/$SCRIPT_NAME"

# 3. Add hook to settings.local.json
HOOK_ENTRY='{
  "matcher": "",
  "hooks": [
    {
      "type": "command",
      "command": "python3 ~/.claude/hooks/allowlist-approve.py"
    }
  ]
}'

if [[ ! -f "$SETTINGS_LOCAL" ]]; then
    # Create new settings file with just the hook
    cat > "$SETTINGS_LOCAL" <<'SETTINGS'
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "python3 ~/.claude/hooks/allowlist-approve.py"
          }
        ]
      }
    ]
  }
}
SETTINGS
    echo "    Created $SETTINGS_LOCAL with hook configuration"
elif python3 -c "
import json, sys
with open('$SETTINGS_LOCAL') as f:
    data = json.load(f)
hooks = data.get('hooks', {}).get('PreToolUse', [])
for h in hooks:
    for inner in h.get('hooks', []):
        if 'allowlist-approve' in inner.get('command', ''):
            sys.exit(0)
sys.exit(1)
" 2>/dev/null; then
    echo "    Hook already configured in $SETTINGS_LOCAL — skipping"
else
    # Merge hook into existing settings
    python3 -c "
import json

with open('$SETTINGS_LOCAL') as f:
    data = json.load(f)

hook_entry = {
    'matcher': '',
    'hooks': [
        {
            'type': 'command',
            'command': 'python3 ~/.claude/hooks/allowlist-approve.py'
        }
    ]
}

data.setdefault('hooks', {}).setdefault('PreToolUse', []).append(hook_entry)

with open('$SETTINGS_LOCAL', 'w') as f:
    json.dump(data, f, indent=2)
    f.write('\n')
"
    echo "    Added hook to existing $SETTINGS_LOCAL"
fi

echo ""
echo "==> Done! The hook will auto-approve tool calls matching your permissions.allow patterns."
echo ""
echo "    Your permissions.allow in any of these files will now work for subagents too:"
echo "      ~/.claude/settings.json"
echo "      ~/.claude/settings.local.json"
echo "      <project>/.claude/settings.json"
echo "      <project>/.claude/settings.local.json"
echo ""
echo "    To test: echo '{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"ls\"}}' | python3 ~/.claude/hooks/allowlist-approve.py"
echo ""
echo "    To uninstall: rm ~/.claude/hooks/allowlist-approve.py"
echo "    Then remove the PreToolUse hook entry from $SETTINGS_LOCAL"
