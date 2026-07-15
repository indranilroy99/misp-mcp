#!/usr/bin/env bash
#
# misp-mcp installer. Sets up the server and wires it into your MCP client.
#
#   ./install.sh
#
# What it does, in order:
#   1. checks your OS and that Python 3.10+ is available (offers to install it)
#   2. creates a virtualenv and installs misp-mcp into it
#   3. asks for your MISP URL and key (the key is never echoed or logged)
#   4. finds your MCP client (Claude Desktop, Claude Code, Cursor, Windsurf)
#      and writes the server config for you; if none is found it prints the
#      exact config and where to paste it
#
# It is safe to re-run: it updates the "misp" entry in place and backs up any
# config file it touches.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$REPO_DIR/.venv"
BIN="$VENV/bin/misp-mcp"
PYTHON=""   # system python, resolved below

# ---------------------------------------------------------------- output helpers
if [ -t 1 ]; then B=$(tput bold 2>/dev/null || true); N=$(tput sgr0 2>/dev/null || true); else B=""; N=""; fi
info() { printf '%s\n' "$*"; }
step() { printf '\n%s==>%s %s\n' "$B" "$N" "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }
ask()  { local p="$1" d="${2:-}" a; if [ -n "$d" ]; then read -r -p "$p [$d]: " a || true; printf '%s' "${a:-$d}"; else read -r -p "$p: " a || true; printf '%s' "$a"; fi; }

banner() {
  cat <<'EOF'

  01001101 01001001 01010011 01010000   01001101 01000011 01010000
   __  __ ___ ___  ___     __  __  ___ ___
  |  \/  |_ _/ __|| _ \   |  \/  |/ __| _ \
  | |\/| || |\__ \|  _/   | |\/| | (__|  _/
  |_|  |_|___|___/|_|     |_|  |_|\___|_|
  Malware Information Sharing Platform  ::  MCP

EOF
}

# ---------------------------------------------------------------- os + python
detect_os() {
  case "$(uname -s)" in
    Darwin) OS="macos" ;;
    Linux)  OS="linux" ;;
    *)      OS="other" ;;
  esac
  info "OS: $OS ($(uname -s) $(uname -m))"
}

py_ok() { "$1" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)' >/dev/null 2>&1; }

resolve_python() {
  local c
  for c in python3.13 python3.12 python3.11 python3.10 python3 python; do
    if command -v "$c" >/dev/null 2>&1 && py_ok "$c"; then PYTHON="$(command -v "$c")"; return 0; fi
  done
  return 1
}

install_python() {
  step "Python 3.10+ not found. Installing it."
  case "$OS" in
    macos)
      if command -v brew >/dev/null 2>&1; then
        [ "$(ask 'Run: brew install python@3.12 ? (y/n)' y)" = "y" ] && brew install python@3.12
      else
        die "Homebrew not found. Install Python 3.10+ from https://www.python.org/downloads/ and re-run."
      fi ;;
    linux)
      local mgr=""
      for m in apt-get dnf yum pacman zypper; do command -v "$m" >/dev/null 2>&1 && { mgr="$m"; break; }; done
      [ -n "$mgr" ] || die "No known package manager. Install Python 3.10+ and python3-venv, then re-run."
      info "Detected package manager: $mgr (needs sudo)."
      command -v sudo >/dev/null 2>&1 || die "sudo not found. Install Python 3.10+ and python3-venv yourself, then re-run."
      [ "$(ask "Install python3 + venv with $mgr ? (y/n)" y)" = "y" ] || die "Install Python 3.10+ yourself, then re-run."
      case "$mgr" in
        apt-get) sudo apt-get update && sudo apt-get install -y python3 python3-venv python3-pip ;;
        dnf|yum) sudo "$mgr" install -y python3 python3-pip ;;
        pacman)  sudo pacman -Sy --noconfirm python python-pip ;;
        zypper)  sudo zypper install -y python3 python3-pip ;;
      esac ;;
    *) die "Unsupported OS. Install Python 3.10+ manually and re-run." ;;
  esac
  resolve_python || die "Python 3.10+ still not found after install."
}

# ---------------------------------------------------------------- venv + package
setup_venv() {
  step "Creating the virtualenv and installing misp-mcp"
  if ! "$PYTHON" -m venv "$VENV" 2>/dev/null; then
    warn "venv creation failed. On Debian/Ubuntu: sudo apt-get install -y python3-venv"
    die "Could not create the virtualenv at $VENV"
  fi
  "$VENV/bin/pip" install --quiet --upgrade pip
  if ! "$VENV/bin/pip" install -e "$REPO_DIR"; then
    die "pip could not install misp-mcp (see the output above)."
  fi
  [ -x "$BIN" ] || die "Install finished but $BIN is missing."
  info "Installed $("$BIN" --version 2>/dev/null || echo misp-mcp). Binary: $BIN"
}

# ---------------------------------------------------------------- credentials
collect_config() {
  step "MISP connection details"
  MISP_URL="$(ask 'MISP URL (e.g. https://misp.example.org)')"
  [ -n "$MISP_URL" ] || die "MISP URL is required."
  printf 'MISP API key (input hidden): '
  read -r -s MISP_API_KEY || true; printf '\n'
  [ -n "$MISP_API_KEY" ] || die "MISP API key is required."
  MISP_EID="$(ask 'Submission event id for misp_submit_ioc (optional, Enter to skip)' '')"

  if [ "$(ask 'Test the connection now? (y/n)' y)" = "y" ]; then
    step "Testing connection"
    if MISP_URL="$MISP_URL" MISP_API_KEY="$MISP_API_KEY" "$VENV/bin/python" "$REPO_DIR/scripts/live_smoke_test.py"; then
      info "Connection OK."
    else
      warn "Smoke test failed (network, VPN, or key). Continuing with config anyway."
    fi
  fi
}

# ---------------------------------------------------------------- client config
write_json_client() {
  local label="$1" cfg="$2"
  mkdir -p "$(dirname "$cfg")"
  [ -f "$cfg" ] && cp -p "$cfg" "$cfg.bak"   # one rolling backup, perms preserved
  MISP_CMD="$BIN" MISP_URL_V="$MISP_URL" MISP_KEY_V="$MISP_API_KEY" MISP_EID_V="${MISP_EID:-}" \
  CFG_PATH="$cfg" "$PYTHON" - <<'PYEOF'
import json, os
cfg = os.environ["CFG_PATH"]
try:
    with open(cfg) as f:
        data = json.load(f)
    if not isinstance(data, dict):
        data = {}
except Exception:
    data = {}
env = {"MISP_URL": os.environ["MISP_URL_V"], "MISP_API_KEY": os.environ["MISP_KEY_V"]}
if os.environ.get("MISP_EID_V"):
    env["MISP_SUBMISSION_EVENT_ID"] = os.environ["MISP_EID_V"]
data.setdefault("mcpServers", {})
data["mcpServers"]["misp"] = {"command": os.environ["MISP_CMD"], "args": [], "env": env}
tmp = cfg + ".tmp"
with open(tmp, "w") as f:
    json.dump(data, f, indent=2)
os.chmod(tmp, 0o600)   # config holds the MISP key in cleartext; keep it owner-only
os.replace(tmp, cfg)
PYEOF
  info "  configured $label -> $cfg"
}

CONFIGURED=0
maybe_configure() {   # ask, then write a JSON-schema client config
  local label="$1" cfg="$2"
  if [ "$(ask "Configure $label? (y/n)" y)" = "y" ]; then
    write_json_client "$label" "$cfg"; CONFIGURED=1
  fi
}

configure_clients() {
  step "Looking for MCP clients"
  CONFIGURED=0

  # JSON-config clients (Claude Desktop, Cursor, Windsurf share the schema).
  local cd_cfg
  if [ "$OS" = "macos" ]; then cd_cfg="$HOME/Library/Application Support/Claude/claude_desktop_config.json"
  else cd_cfg="$HOME/.config/Claude/claude_desktop_config.json"; fi

  if [ -e "$cd_cfg" ] || [ -d "$(dirname "$cd_cfg")" ]; then maybe_configure "Claude Desktop" "$cd_cfg"; fi
  if [ -e "$HOME/.cursor/mcp.json" ] || [ -d "$HOME/.cursor" ]; then maybe_configure "Cursor" "$HOME/.cursor/mcp.json"; fi
  if [ -e "$HOME/.codeium/windsurf/mcp_config.json" ] || [ -d "$HOME/.codeium/windsurf" ]; then maybe_configure "Windsurf" "$HOME/.codeium/windsurf/mcp_config.json"; fi

  # Claude Code (CLI): use its own command so it records the server properly.
  # Note: `claude mcp add` takes the key as a CLI argument, briefly visible in
  # `ps` to local users. On a shared host, run this step yourself instead.
  if command -v claude >/dev/null 2>&1 && [ "$(ask 'Configure Claude Code (claude CLI)? (y/n)' y)" = "y" ]; then
    local cargs=(--env "MISP_URL=$MISP_URL" --env "MISP_API_KEY=$MISP_API_KEY")
    [ -n "${MISP_EID:-}" ] && cargs+=(--env "MISP_SUBMISSION_EVENT_ID=$MISP_EID")
    claude mcp remove misp >/dev/null 2>&1 || true
    local out
    if out="$(claude mcp add misp --scope user "${cargs[@]}" -- "$BIN" 2>&1)"; then
      info "  configured Claude Code (claude mcp add)"; CONFIGURED=1
    else
      warn "claude mcp add failed: $out"
    fi
  fi

  if [ "$CONFIGURED" -eq 0 ]; then manual_fallback; fi
}

manual_fallback() {
  step "No MCP client detected. Add this to your client's MCP config"
  cat <<EOF

  {
    "mcpServers": {
      "misp": {
        "command": "$BIN",
        "args": [],
        "env": {
          "MISP_URL": "$MISP_URL",
          "MISP_API_KEY": "<your key>"$([ -n "${MISP_EID:-}" ] && printf ',\n          "MISP_SUBMISSION_EVENT_ID": "%s"' "$MISP_EID")
        }
      }
    }
  }

  Common config locations:
    Claude Desktop (macOS): ~/Library/Application Support/Claude/claude_desktop_config.json
    Claude Desktop (Linux): ~/.config/Claude/claude_desktop_config.json
    Cursor:                 ~/.cursor/mcp.json
    Windsurf:               ~/.codeium/windsurf/mcp_config.json
    Claude Code (CLI):      claude mcp add misp --env MISP_URL=$MISP_URL --env MISP_API_KEY=<key> -- $BIN
EOF
}

main() {
  banner
  detect_os
  step "Checking Python"
  resolve_python || install_python
  info "Using Python: $PYTHON ($("$PYTHON" -V 2>&1))"
  setup_venv
  collect_config
  configure_clients
  step "Done"
  info "Restart your MCP client, then ask it: \"Look up 8.8.8.8 in MISP.\""
  info "Hosting for a team instead? See DEPLOY.md (self-host) and CLOUD.md (AWS/GCP/Azure)."
}

# Only auto-run when executed directly, so the functions can be sourced/tested.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  main "$@"
fi
