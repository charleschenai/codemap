#!/bin/bash
# Codemap — Claude Code Plugin Installer
# Installs the /codemap skill into Claude Code's plugin system.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/charleschenai/codemap/main/install.sh | bash
#   # or after cloning:
#   bash install.sh

set -euo pipefail

PLUGIN_DIR="$HOME/.claude/plugins/marketplaces/codemap"
CACHE_DIR="$HOME/.claude/plugins/cache/codemap"
SETTINGS="$HOME/.claude/settings.json"
REPO_URL="${CODEMAP_REPO:-https://github.com/charleschenai/codemap.git}"

echo "=== Codemap Installer ==="

# 1. Clone or update the repo
if [ -d "$PLUGIN_DIR/.git" ]; then
    echo "Plugin already cloned at $PLUGIN_DIR, pulling latest..."
    cd "$PLUGIN_DIR" && git pull --ff-only 2>/dev/null || true
else
    echo "Cloning to $PLUGIN_DIR..."
    mkdir -p "$(dirname "$PLUGIN_DIR")"
    # Clean up any broken install
    rm -rf "$PLUGIN_DIR"
    git clone "$REPO_URL" "$PLUGIN_DIR"
fi

# 2. Verify required files exist
for f in .claude-plugin/marketplace.json plugin/.claude-plugin/plugin.json plugin/skills/codemap/SKILL.md; do
    if [ ! -f "$PLUGIN_DIR/$f" ]; then
        echo "ERROR: Missing $f — clone may be corrupt"
        exit 1
    fi
done

# 3. Clear stale plugin cache (Claude Code reads from cache, not source)
if [ -d "$CACHE_DIR" ]; then
    echo "Clearing stale plugin cache..."
    rm -rf "$CACHE_DIR"
fi

# 4. Update settings.json
if [ ! -f "$SETTINGS" ]; then
    echo "Creating $SETTINGS..."
    mkdir -p "$(dirname "$SETTINGS")"
    cat > "$SETTINGS" << 'ENDJSON'
{
  "enabledPlugins": {
    "codemap@codemap": true
  },
  "extraKnownMarketplaces": {
    "codemap": {
      "source": {
        "source": "directory",
        "path": "PLUGIN_DIR_PLACEHOLDER"
      }
    }
  }
}
ENDJSON
    sed -i '' "s|PLUGIN_DIR_PLACEHOLDER|$PLUGIN_DIR|g" "$SETTINGS"
else
    if command -v python3 &>/dev/null; then
        python3 << PYEOF
import json

settings_path = "$SETTINGS"
plugin_dir = "$PLUGIN_DIR"

with open(settings_path, "r") as f:
    settings = json.load(f)

changed = False

# Add enabledPlugins
if "enabledPlugins" not in settings:
    settings["enabledPlugins"] = {}
if "codemap@codemap" not in settings.get("enabledPlugins", {}):
    settings["enabledPlugins"]["codemap@codemap"] = True
    changed = True

# Add extraKnownMarketplaces
if "extraKnownMarketplaces" not in settings:
    settings["extraKnownMarketplaces"] = {}
if "codemap" not in settings.get("extraKnownMarketplaces", {}):
    settings["extraKnownMarketplaces"]["codemap"] = {
        "source": {
            "source": "directory",
            "path": plugin_dir
        }
    }
    changed = True

if changed:
    with open(settings_path, "w") as f:
        json.dump(settings, f, indent=2)
    print("Updated settings.json")
else:
    print("settings.json already configured")
PYEOF
    else
        echo "WARNING: python3 not found — please add these entries to $SETTINGS manually:"
        echo ""
        echo '  "enabledPlugins": { "codemap@codemap": true }'
        echo '  "extraKnownMarketplaces": { "codemap": { "source": { "source": "directory", "path": "'$PLUGIN_DIR'" } } }'
    fi
fi

# 5. Install the codemap binary
echo ""
if command -v cargo &>/dev/null; then
    echo "Building codemap from source..."
    cd "$PLUGIN_DIR"
    cargo build --release -p codemap-cli 2>&1 | tail -1

    # Install to ~/bin
    mkdir -p "$HOME/bin"
    cp "$PLUGIN_DIR/target/release/codemap" "$HOME/bin/codemap"
    echo "Installed binary to ~/bin/codemap"

    # Ensure ~/bin is on PATH
    if ! echo "$PATH" | tr ':' '\n' | grep -qx "$HOME/bin"; then
        echo ""
        echo "NOTE: Add ~/bin to your PATH if not already:"
        echo '  export PATH="$HOME/bin:$PATH"'
    fi
else
    echo "WARNING: cargo not found — skipping binary build."
    echo "Install Rust (https://rustup.rs) then re-run, or build manually:"
    echo "  cd $PLUGIN_DIR && cargo build --release -p codemap-cli"
    echo "  cp target/release/codemap ~/bin/"
fi

echo ""
echo "=== Installed successfully ==="
echo "Restart Claude Code to pick up the /codemap skill."
echo "Usage: codemap --dir <path> <action> [target]"
echo "       /codemap in Claude Code for guided analysis"
