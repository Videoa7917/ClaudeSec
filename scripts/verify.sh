#!/usr/bin/env bash
# =============================================================================
# ClaudeSec — Tool Installation Verifier
# Version: 2.1.0
# =============================================================================
# Usage: ./scripts/verify.sh
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0

check_tool() {
    local tool=$1
    local version_flag=${2:---version}
    local category=${3:-general}

    if command -v "$tool" &>/dev/null; then
        local ver
        ver=$($tool $version_flag 2>/dev/null | head -1 || echo "installed")
        printf "  ${GREEN}✓${NC} %-15s %s\n" "$tool" "$ver"
        PASS=$((PASS + 1))
    else
        printf "  ${RED}✗${NC} %-15s not found\n" "$tool"
        FAIL=$((FAIL + 1))
    fi
}

check_python_module() {
    local module=$1
    local import_name=${2:-$1}

    if python3 -c "import $import_name" &>/dev/null 2>&1; then
        printf "  ${GREEN}✓${NC} %-15s (Python)\n" "$module"
        PASS=$((PASS + 1))
    else
        printf "  ${YELLOW}─${NC} %-15s not installed\n" "$module"
        WARN=$((WARN + 1))
    fi
}

echo -e "${BLUE}"
echo '  ╔══════════════════════════════════════╗'
echo '  ║     ClaudeSec Tool Verification      ║'
echo '  ╚══════════════════════════════════════╝'
echo -e "${NC}"

echo -e "\n${BLUE}[ System Tools ]${NC}"
check_tool nmap
check_tool whatweb
check_tool dirsearch
check_tool curl
check_tool wget
check_tool git
check_tool python3
check_tool pip3
check_tool sqlmap

echo -e "\n${BLUE}[ Go Tools ]${NC}"
check_tool subfinder "-v"
check_tool ffuf "-V"
check_tool httpx
check_tool hakrawler
check_tool waybackurls
check_tool gf
check_tool naabu
check_tool gau
check_tool nuclei
check_tool interactsh-client

echo -e "\n${BLUE}[ Python Modules ]${NC}"
check_python_module requests
check_python_module bs4 beautifulsoup4
check_python_module arjun

echo -e "\n${BLUE}[ Summary ]${NC}"
echo -e "  ${GREEN}${PASS} available${NC}, ${YELLOW}${WARN} optional${NC}, ${RED}${FAIL} missing${NC}"

if [ $FAIL -gt 0 ]; then
    echo -e "\n  ${YELLOW}Tip: Run ./scripts/install.sh to install missing tools${NC}"
fi

exit $FAIL
