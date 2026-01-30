#!/bin/bash

##############################################################################
# GitHub Repository Setup Script
# Repository: https://github.com/speedshadow/rstprx
##############################################################################

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo ""
echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║                                                                   ║"
echo "║           GitHub Repository Setup - rstprx                       ║"
echo "║                                                                   ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo ""

# Check if git is installed
if ! command -v git &> /dev/null; then
    echo -e "${RED}[ERROR]${NC} Git is not installed"
    echo "Install with: sudo apt install git"
    exit 1
fi

echo -e "${BLUE}[INFO]${NC} Checking current git status..."

# Check if already a git repository
if [ -d .git ]; then
    echo -e "${YELLOW}[WARN]${NC} This is already a git repository"
    echo -e "${YELLOW}[WARN]${NC} Existing remote:"
    git remote -v || echo "No remote configured"
    echo ""
    read -p "Remove existing .git and start fresh? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf .git
        echo -e "${GREEN}[SUCCESS]${NC} Removed existing git repository"
    else
        echo -e "${YELLOW}[WARN]${NC} Keeping existing repository"
        echo -e "${BLUE}[INFO]${NC} You can manually add remote with:"
        echo "    git remote add origin https://github.com/speedshadow/rstprx.git"
        exit 0
    fi
fi

# Initialize git repository
echo -e "${BLUE}[INFO]${NC} Initializing git repository..."
git init
echo -e "${GREEN}[SUCCESS]${NC} Git repository initialized"

# Set default branch to main
git branch -M main

# Add all files
echo -e "${BLUE}[INFO]${NC} Adding files to git..."
git add .

# Create initial commit
echo -e "${BLUE}[INFO]${NC} Creating initial commit..."
git commit -m "Initial commit: RstPrx - Elite Rama Reverse Proxy

Features:
- JA3/JA4+ fingerprint spoofing
- Auto SSL/ACME with renewal
- Circuit breaker & rate limiting
- Stealth mode with fake websites
- JWT authentication
- Production-ready systemd service
- 100% automated installer

Built with Rust 🦀 and Rama framework"

echo -e "${GREEN}[SUCCESS]${NC} Initial commit created"

# Add remote
echo ""
echo -e "${BLUE}[INFO]${NC} Adding GitHub remote..."
git remote add origin https://github.com/speedshadow/rstprx.git
echo -e "${GREEN}[SUCCESS]${NC} Remote added: origin → https://github.com/speedshadow/rstprx.git"

echo ""
echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║                                                                   ║"
echo "║                   ✅ Git Setup Complete!                          ║"
echo "║                                                                   ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo ""
echo -e "${YELLOW}📋 Next Steps:${NC}"
echo ""
echo -e "${BLUE}1. Create GitHub repository:${NC}"
echo "   → Go to: https://github.com/new"
echo "   → Repository name: ${GREEN}rstprx${NC}"
echo "   → Description: ${GREEN}Elite Rama Reverse Proxy - Production-ready 2026${NC}"
echo "   → Public repository"
echo "   → Do NOT initialize with README (we already have one)"
echo ""
echo -e "${BLUE}2. Push to GitHub:${NC}"
echo "   ${GREEN}git push -u origin main${NC}"
echo ""
echo -e "${BLUE}3. Configure repository (optional):${NC}"
echo "   → Add topics: rust, reverse-proxy, rama, proxy, acme, ssl"
echo "   → Enable Issues"
echo "   → Enable Discussions"
echo "   → Add LICENSE file"
echo ""
echo -e "${YELLOW}⚠️  Important:${NC}"
echo "   Make sure you have created the repository on GitHub first!"
echo "   Then run: ${GREEN}git push -u origin main${NC}"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
