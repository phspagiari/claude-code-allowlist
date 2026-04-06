#!/bin/bash
# install.sh — Install the claude-code-allowlist hooks
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/phspagiari/claude-code-allowlist/main/install.sh | bash
#
# Or from a local clone:
#   ./install.sh

set -euo pipefail

HOOKS_DIR="$HOME/.claude/hooks"
SETTINGS_LOCAL="$HOME/.claude/settings.local.json"
REPO_RAW="https://raw.githubusercontent.com/phspagiari/claude-code-allowlist/main"

SCRIPTS=("allowlist-approve.py" "allowlist-learn.py")

echo "==> Installing claude-code-allowlist hooks..."

# 1. Create hooks directory
mkdir -p "$HOOKS_DIR"

# 2. Download or copy both hook scripts
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
for script in "${SCRIPTS[@]}"; do
    if [[ -f "$SCRIPT_DIR/$script" ]]; then
        cp "$SCRIPT_DIR/$script" "$HOOKS_DIR/$script"
        echo "    Copied from local: $SCRIPT_DIR/$script"
    else
        curl -fsSL "$REPO_RAW/$script" -o "$HOOKS_DIR/$script"
        echo "    Downloaded from: $REPO_RAW/$script"
    fi
    chmod +x "$HOOKS_DIR/$script"
    echo "    Installed to: $HOOKS_DIR/$script"
done

# 3. Add hooks to settings.local.json
add_hook() {
    local event="$1"
    local command="$2"
    local marker="$3"

    if python3 -c "
import json, sys
with open('$SETTINGS_LOCAL') as f:
    data = json.load(f)
hooks = data.get('hooks', {}).get('$event', [])
for h in hooks:
    for inner in h.get('hooks', []):
        if '$marker' in inner.get('command', ''):
            sys.exit(0)
sys.exit(1)
" 2>/dev/null; then
        echo "    $event hook already configured — skipping"
    else
        python3 -c "
import json

with open('$SETTINGS_LOCAL') as f:
    data = json.load(f)

hook_entry = {
    'matcher': '',
    'hooks': [
        {
            'type': 'command',
            'command': '$command'
        }
    ]
}

data.setdefault('hooks', {}).setdefault('$event', []).append(hook_entry)

with open('$SETTINGS_LOCAL', 'w') as f:
    json.dump(data, f, indent=2)
    f.write('\n')
"
        echo "    Added $event hook to $SETTINGS_LOCAL"
    fi
}

if [[ ! -f "$SETTINGS_LOCAL" ]]; then
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
    ],
    "PostToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "python3 ~/.claude/hooks/allowlist-learn.py"
          }
        ]
      }
    ]
  }
}
SETTINGS
    echo "    Created $SETTINGS_LOCAL with hook configuration"
else
    add_hook "PreToolUse" "python3 ~/.claude/hooks/allowlist-approve.py" "allowlist-approve"
    add_hook "PostToolUse" "python3 ~/.claude/hooks/allowlist-learn.py" "allowlist-learn"
fi

echo ""
echo "==> Done! Two hooks installed:"
echo ""
echo "    PreToolUse  (allowlist-approve.py) — auto-approves safe tool calls"
echo "    PostToolUse (allowlist-learn.py)   — learns from your manual approvals"
echo ""
echo "    Learned patterns are saved to: ~/.claude/learned-allowlist.json"
echo ""
echo "    To test:"
echo "      echo '{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"ls\"}}' | python3 ~/.claude/hooks/allowlist-approve.py"
echo ""
echo "    To uninstall:"
echo "      rm ~/.claude/hooks/allowlist-approve.py ~/.claude/hooks/allowlist-learn.py"
echo "      rm ~/.claude/learned-allowlist.json"
echo "      Then remove the PreToolUse and PostToolUse hook entries from $SETTINGS_LOCAL"
