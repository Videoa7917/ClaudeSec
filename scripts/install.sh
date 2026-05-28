#!/usr/bin/env bash
# =============================================================================
# ClaudeSec — Automated Dependency Installer
# Version: 2.0.0
# =============================================================================
#
# This script installs all required dependencies for ClaudeSec.
# Supports: Ubuntu/Debian (apt), WSL2
#
# Usage:
#   chmod +x scripts/install.sh
#   ./scripts/install.sh          # Full installation
#   ./scripts/install.sh --min    # Minimal installation (core tools only)
#   ./scripts/install.sh --verify # Only verify existing installation
# =============================================================================

set -euo pipefail

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# --- Counters ---
SUCCESS=0
FAILED=0
SKIPPED=0

log_info()    { echo -e "${BLUE}[*]${NC} $1"; }
log_ok()      { echo -e "${GREEN}[✓]${NC} $1"; SUCCESS=$((SUCCESS + 1)); }
log_warn()    { echo -e "${YELLOW}[!]${NC} $1"; SKIPPED=$((SKIPPED + 1)); }
log_error()   { echo -e "${RED}[✗]${NC} $1"; FAILED=$((FAILED + 1)); }
log_section() { echo -e "\n${BLUE}═══════════════════════════════════════════${NC}"; echo -e "${BLUE}  $1${NC}"; echo -e "${BLUE}═══════════════════════════════════════════${NC}"; }

# --- Pre-flight checks ---
check_prerequisites() {
    log_section "Pre-flight Checks"

    # OS detection
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        log_ok "OS detected: $NAME $VERSION_ID"
    else
        log_warn "Could not detect OS. Assuming Debian-based."
    fi

    # Architecture
    ARCH=$(uname -m)
    log_ok "Architecture: $ARCH"

    # Sudo check
    if ! command -v sudo &>/dev/null; then
        log_error "sudo is required but not installed."
        exit 1
    fi
    log_ok "sudo available"

    # Internet connectivity
    if ping -c 1 -W 2 8.8.8.8 &>/dev/null; then
        log_ok "Internet connectivity confirmed"
    else
        log_warn "No internet connectivity detected (some tools may fail)"
    fi
}

# --- System packages ---
install_system_packages() {
    log_section "System Packages"

    local packages=(
        nmap
        whatweb
        dirsearch
        curl
        wget
        git
        python3
        python3-pip
        python3-venv
        build-essential
    )

    log_info "Installing: ${packages[*]}"
    sudo apt update -qq && sudo apt install -y -qq "${packages[@]}" 2>/dev/null

    for pkg in "${packages[@]}"; do
        if dpkg -l "$pkg" &>/dev/null 2>&1; then
            log_ok "$pkg installed"
        else
            log_warn "$pkg status unknown"
        fi
    done
}

# --- Go tools ---
install_go_tools() {
    log_section "Go Tools"

    # Check Go
    if ! command -v go &>/dev/null; then
        log_info "Go not found. Installing Go 1.21..."
        wget -q https://go.dev/dl/go1.21.13.linux-amd64.tar.gz -O /tmp/go.tar.gz
        sudo tar -C /usr/local -xzf /tmp/go.tar.gz
        echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
        export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
        rm /tmp/go.tar.gz
        log_ok "Go installed: $(go version)"
    else
        log_ok "Go found: $(go version)"
    fi

    # Core Go tools (always install)
    local core_tools=(
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "github.com/ffuf/ffuf/v2@latest"
        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    )

    for tool in "${core_tools[@]}"; do
        local tool_name
        tool_name=$(basename "$(dirname "$tool")")
        if command -v "$tool_name" &>/dev/null; then
            log_ok "$tool_name already installed: $($tool_name -version 2>/dev/null || echo 'ok')"
        else
            log_info "Installing $tool_name..."
            go install "$tool" &>/tmp/go_install.log && \
                log_ok "$tool_name installed" || \
                log_error "$tool_name failed to install (see /tmp/go_install.log)"
        fi
    done

    # If --min mode, skip optional tools
    if [ "${1:-}" = "--min" ]; then
        log_info "Skipping optional Go tools (--min mode)"
        return
    fi

    # Optional Go tools
    local optional_tools=(
        "github.com/hakluke/hakrawler@latest"
        "github.com/tomnomnom/waybackurls@latest"
        "github.com/tomnomnom/gf@latest"
        "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
        "github.com/lc/gau@latest"
    )

    for tool in "${optional_tools[@]}"; do
        local tool_name
        tool_name=$(basename "$(dirname "$tool")")
        if command -v "$tool_name" &>/dev/null; then
            log_ok "$tool_name already installed"
        else
            log_info "Installing $tool_name..."
            go install "$tool" &>/tmp/go_install.log && \
                log_ok "$tool_name installed" || \
                log_warn "$tool_name installation failed (optional)"
        fi
    done
}

# --- Python tools ---
install_python_tools() {
    log_section "Python Tools"

    local tools=(
        "uro"
        "beautifulsoup4"
        "requests"
        "argparse"
    )

    for tool in "${tools[@]}"; do
        if python3 -c "import ${tool/beautifulsoup4/bs4}" &>/dev/null 2>&1; then
            log_ok "${tool} already installed"
        else
            pip3 install -q "$tool" 2>/dev/null && \
                log_ok "${tool} installed" || \
                log_warn "${tool} installation failed (optional)"
        fi
    done

    # Optional: arjun, git-dumper
    pip3 install arjun git-dumper 2>/dev/null && \
        log_ok "arjun, git-dumper installed" || \
        log_warn "arjun/git-dumper installation failed (optional)"
}

# --- Verification ---
verify_installation() {
    log_section "Installation Verification"

    local all_tools=(
        nmap whatweb dirsearch curl wget git python3
        subfinder ffuf httpx
    )

    local optional_tools=(
        hakrawler waybackurls gf naabu gau
        sqlmap arjun git-dumper
    )

    echo ""
    echo "  Core Tools:"
    for tool in "${all_tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            echo -e "    ${GREEN}✓${NC} $tool"
        else
            echo -e "    ${RED}✗${NC} $tool (missing)"
        fi
    done

    echo ""
    echo "  Optional Tools:"
    for tool in "${optional_tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            echo -e "    ${GREEN}✓${NC} $tool"
        else
            echo -e "    ${YELLOW}─${NC} $tool (not installed)"
        fi
    done

    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════${NC}"
    echo -e "  ${GREEN}${SUCCESS} installed${NC}, ${YELLOW}${SKIPPED} skipped${NC}, ${RED}${FAILED} failed${NC}"
}

# --- Main ---
main() {
    echo -e "${BLUE}"
    echo '   ___ _           ___            '
    echo '  / __| |_  ___   / __| ___  ___  '
    echo ' | (__| ` \/ _ \  \__ \/ _ \/ _ \ '
    echo '  \___|_||_\___/  |___/\___/\___/ '
    echo -e "${NC}"
    echo "  ClaudeSec Installer v2.0.0"
    echo "  AI-Driven Security Testing Framework"
    echo ""

    check_prerequisites
    install_system_packages
    install_go_tools "${1:-}"
    install_python_tools
    verify_installation

    echo ""
    echo -e "${GREEN}Installation complete!${NC}"
    echo "Run 'source ~/.bashrc' or restart your terminal to update PATH."
    echo "Then verify with: ./scripts/install.sh --verify"
    echo ""
    echo "Quick start:"
    echo "  /recon example.com    # Reconnaissance"
    echo "  /scan example.com     # Vulnerability scan"
    echo "  /report               # Generate report"
}

main "$@"
