#!/bin/bash
# Codemap — Claude Code Plugin Installer
# 54-action codebase analysis with native Rust tree-sitter AST across 12 languages.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/charleschenai/codemap/main/install.sh | bash
#   bash install.sh            # after cloning
#   bash install.sh --check    # verify install
#   bash install.sh --uninstall

set -euo pipefail

PLUGIN_NAME="codemap"
PLUGIN_KEY="codemap@codemap"
PLUGIN_DIR="$HOME/.claude/plugins/marketplaces/$PLUGIN_NAME"
CACHE_DIR="$HOME/.claude/plugins/cache/$PLUGIN_NAME"
SETTINGS="$HOME/.claude/settings.json"
REPO_URL="${CODEMAP_REPO:-https://github.com/charleschenai/codemap.git}"
REQUIRED_FILES=(
    ".claude-plugin/marketplace.json"
    "plugin/.claude-plugin/plugin.json"
    "plugin/skills/codemap/SKILL.md"
)

info()  { printf "\033[0;36m[*]\033[0m %s\n" "$*"; }
ok()    { printf "\033[0;32m[+]\033[0m %s\n" "$*"; }
warn()  { printf "\033[1;33m[!]\033[0m %s\n" "$*"; }
fail()  { printf "\033[0;31m[x]\033[0m %s\n" "$*"; exit 1; }

# --- Uninstall ---
if [ "${1:-}" = "--uninstall" ]; then
    info "Uninstalling $PLUGIN_NAME..."
    rm -rf "$PLUGIN_DIR" "$CACHE_DIR"
    if [ -f "$HOME/bin/codemap" ]; then
        rm -f "$HOME/bin/codemap"
        info "Removed ~/bin/codemap binary"
    fi
    if [ -f "/usr/local/bin/codemap" ]; then
        info "Note: /usr/local/bin/codemap still exists (may need sudo to remove)"
    fi
    ok "Removed plugin and cache."
    exit 0
fi

# --- Check ---
if [ "${1:-}" = "--check" ]; then
    echo "=== $PLUGIN_NAME Plugin Status ==="
    all_ok=true
    for f in "${REQUIRED_FILES[@]}"; do
        if [ -f "$PLUGIN_DIR/$f" ]; then
            ok "$f"
        else
            warn "MISSING: $f"
            all_ok=false
        fi
    done
    if [ -d "$CACHE_DIR" ]; then
        ok "Cache exists"
    else
        info "No cache (created on next Claude Code start)"
    fi
    if [ -f "$SETTINGS" ] && grep -q "$PLUGIN_KEY" "$SETTINGS" 2>/dev/null; then
        ok "settings.json configured"
    else
        warn "Not in settings.json"
        all_ok=false
    fi
    if command -v codemap &>/dev/null; then
        ok "codemap binary: $(codemap --version 2>/dev/null || echo 'found')"
    else
        warn "codemap binary not on PATH"
        all_ok=false
    fi
    $all_ok && ok "Status: installed" || warn "Status: needs attention"
    exit 0
fi

echo "=== $PLUGIN_NAME Installer ==="

# --- Prerequisites ---
command -v git &>/dev/null || fail "git is required but not installed. Install git first."

# --- Clone or update ---
if [ -d "$PLUGIN_DIR/.git" ]; then
    info "Already installed, pulling latest..."
    cd "$PLUGIN_DIR" && git pull --ff-only 2>/dev/null || true
else
    info "Cloning to $PLUGIN_DIR..."
    mkdir -p "$(dirname "$PLUGIN_DIR")"
    rm -rf "$PLUGIN_DIR"
    git clone "$REPO_URL" "$PLUGIN_DIR"
fi

# --- Verify ---
for f in "${REQUIRED_FILES[@]}"; do
    [ -f "$PLUGIN_DIR/$f" ] || fail "Missing $f — clone may be corrupt"
done
ok "All required files present"

# --- Clear stale cache ---
if [ -d "$CACHE_DIR" ]; then
    info "Clearing stale plugin cache..."
    rm -rf "$CACHE_DIR"
fi

# --- Update settings.json ---
if command -v python3 &>/dev/null; then
    python3 << PYEOF
import json, os

settings_path = os.path.expanduser("$SETTINGS")
plugin_dir = os.path.expanduser("$PLUGIN_DIR")

os.makedirs(os.path.dirname(settings_path), exist_ok=True)

if os.path.exists(settings_path):
    with open(settings_path, "r") as f:
        settings = json.load(f)
else:
    settings = {}

changed = False

if "enabledPlugins" not in settings:
    settings["enabledPlugins"] = {}
if "$PLUGIN_KEY" not in settings["enabledPlugins"]:
    settings["enabledPlugins"]["$PLUGIN_KEY"] = True
    changed = True

if "extraKnownMarketplaces" not in settings:
    settings["extraKnownMarketplaces"] = {}
if "$PLUGIN_NAME" not in settings["extraKnownMarketplaces"]:
    settings["extraKnownMarketplaces"]["$PLUGIN_NAME"] = {
        "source": {"source": "directory", "path": plugin_dir}
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
    warn "python3 not found — add these to $SETTINGS manually:"
    echo "  \"enabledPlugins\": { \"$PLUGIN_KEY\": true }"
    echo "  \"extraKnownMarketplaces\": { \"$PLUGIN_NAME\": { \"source\": { \"source\": \"directory\", \"path\": \"$PLUGIN_DIR\" } } }"
fi

# --- Build codemap binary ---
echo ""
info "Installing codemap binary..."

# Detect platform for install path
BIN_DIR="$HOME/bin"
if [ "$(id -u)" = "0" ]; then
    BIN_DIR="/usr/local/bin"
fi

if command -v cargo &>/dev/null; then
    info "Building from source (this may take a minute)..."
    cd "$PLUGIN_DIR"
    cargo build --release -p codemap-cli 2>&1 | tail -3
    mkdir -p "$BIN_DIR"
    cp "$PLUGIN_DIR/target/release/codemap" "$BIN_DIR/codemap"
    chmod +x "$BIN_DIR/codemap"
    ok "Installed binary to $BIN_DIR/codemap"
else
    warn "Rust toolchain not found — cannot build codemap binary."
    echo ""
    echo "  Option 1: Install Rust and re-run"
    echo "    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    echo "    bash $PLUGIN_DIR/install.sh"
    echo ""
    echo "  Option 2: Copy a pre-built binary to $BIN_DIR/codemap"
    echo "    (get one from a machine that has Rust installed)"
    echo ""
    echo "  The /codemap Claude Code skill is installed either way,"
    echo "  but the binary is needed for it to work."
fi

# Check PATH
if ! echo "$PATH" | tr ':' '\n' | grep -qx "$BIN_DIR"; then
    echo ""
    warn "Add $BIN_DIR to your PATH:"
    echo "  export PATH=\"$BIN_DIR:\$PATH\""
    echo "  Add this to your ~/.bashrc or ~/.zshrc"
fi

echo ""
ok "Installed successfully!"
echo "Restart Claude Code, then use: /codemap"
echo "CLI: codemap --dir <path> <action> [target]"
echo ""
echo "  --check      Verify installation"
echo "  --uninstall  Remove plugin"
