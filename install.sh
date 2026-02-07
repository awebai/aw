#!/usr/bin/env bash
#
# aw (aweb CLI) installation script
# Usage: curl -fsSL https://raw.githubusercontent.com/awebai/aw/main/install.sh | bash
#
# Security note: For maximum security, download and inspect the script first:
#   curl -fsSL https://raw.githubusercontent.com/awebai/aw/main/install.sh > install.sh
#   less install.sh  # Review the script
#   bash install.sh
#
# IMPORTANT: This script must be EXECUTED, never SOURCED
# WRONG: source install.sh (will exit your shell on errors)
# CORRECT: bash install.sh
# CORRECT: curl -fsSL ... | bash

set -e

REPO="awebai/aw"
BINARY="aw"

# Track where we installed for PATH warning messages
LAST_INSTALL_PATH=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}==>${NC} $1"
}

log_success() {
    echo -e "${GREEN}==>${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}==>${NC} $1"
}

log_error() {
    echo -e "${RED}Error:${NC} $1" >&2
}

# Detect OS and architecture
detect_platform() {
    local os arch

    case "$(uname -s)" in
        Darwin)
            os="darwin"
            ;;
        Linux)
            os="linux"
            ;;
        MINGW*|MSYS*|CYGWIN*)
            os="windows"
            ;;
        *)
            log_error "Unsupported operating system: $(uname -s)"
            exit 1
            ;;
    esac

    case "$(uname -m)" in
        x86_64|amd64)
            arch="amd64"
            ;;
        aarch64|arm64)
            arch="arm64"
            ;;
        *)
            log_error "Unsupported architecture: $(uname -m)"
            exit 1
            ;;
    esac

    echo "${os}_${arch}"
}

# Re-sign binary for macOS to avoid slow Gatekeeper checks
resign_for_macos() {
    local binary_path=$1

    if [[ "$(uname -s)" != "Darwin" ]]; then
        return 0
    fi

    if ! command -v codesign >/dev/null 2>&1; then
        return 0
    fi

    log_info "Re-signing binary for macOS..."
    codesign --remove-signature "$binary_path" 2>/dev/null || true
    if codesign --force --sign - "$binary_path"; then
        log_success "Binary re-signed for this machine"
    else
        log_warning "Failed to re-sign binary (non-fatal)"
    fi
}

# Get the latest release version
get_latest_version() {
    local response

    log_info "Fetching latest release..."

    if command -v curl >/dev/null 2>&1; then
        response=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest")
    elif command -v wget >/dev/null 2>&1; then
        response=$(wget -qO- "https://api.github.com/repos/$REPO/releases/latest")
    else
        log_error "Neither curl nor wget found. Please install one of them."
        exit 1
    fi

    # Store full response for asset checking
    RELEASE_JSON="$response"

    VERSION=$(echo "$response" | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/' | head -1)

    if [ -z "$VERSION" ]; then
        log_error "Could not determine latest version"
        exit 1
    fi

    log_info "Latest version: v$VERSION"
}

# Check if release has a specific asset
release_has_asset() {
    local asset_name=$1

    if echo "$RELEASE_JSON" | grep -Fq "\"name\": \"$asset_name\""; then
        return 0
    fi

    return 1
}

# Verify checksum of downloaded file
verify_checksum() {
    local file="$1"
    local checksums_file="$2"
    local filename
    filename=$(basename "$file")
    local expected actual

    log_info "Verifying checksum..."

    if command -v sha256sum >/dev/null 2>&1; then
        expected=$(grep "$filename" "$checksums_file" | awk '{print $1}')
        actual=$(sha256sum "$file" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        expected=$(grep "$filename" "$checksums_file" | awk '{print $1}')
        actual=$(shasum -a 256 "$file" | awk '{print $1}')
    else
        log_error "sha256sum or shasum required for checksum verification"
        exit 1
    fi

    if [ "$expected" != "$actual" ]; then
        log_error "Checksum verification failed!"
        echo "  Expected: $expected"
        echo "  Actual:   $actual"
        exit 1
    fi

    log_success "Checksum verified"
}

# Verify installation
verify_installation() {
    if command -v aw >/dev/null 2>&1; then
        log_success "aw is installed and ready!"
        echo ""
        aw version 2>/dev/null || echo "aw (development build)"
        echo ""
        echo "Get started:"
        echo "  aw init --cloud    # Bootstrap agent via aweb cloud"
        echo "  aw --help          # See all commands"
        echo ""
        return 0
    else
        log_error "aw was installed but is not in PATH"
        return 1
    fi
}

# Download and install from GitHub releases
install_from_release() {
    local platform=$1
    local tmp_dir
    tmp_dir=$(mktemp -d)

    get_latest_version

    local ext="tar.gz"
    local binary="aw"
    if [[ "$platform" == windows_* ]]; then
        ext="zip"
        binary="aw.exe"
    fi

    local archive_name="${binary}_${VERSION}_${platform}.${ext}"
    local url="https://github.com/$REPO/releases/download/v$VERSION/$archive_name"
    local checksums_url="https://github.com/$REPO/releases/download/v$VERSION/checksums.txt"

    if ! release_has_asset "$archive_name"; then
        log_warning "No prebuilt archive available for platform ${platform}."
        rm -rf "$tmp_dir"
        return 1
    fi

    local skip_checksum=""
    if ! release_has_asset "checksums.txt"; then
        log_warning "Checksums not available for this release, skipping verification"
        skip_checksum=1
    fi

    log_info "Downloading $archive_name..."

    cd "$tmp_dir"
    if command -v curl >/dev/null 2>&1; then
        if ! curl -fsSL -o "$archive_name" "$url"; then
            log_error "Download failed"
            cd - > /dev/null || cd "$HOME"
            rm -rf "$tmp_dir"
            return 1
        fi
        if [ -z "$skip_checksum" ]; then
            if ! curl -fsSL -o "checksums.txt" "$checksums_url"; then
                log_warning "Failed to download checksums, skipping verification"
                skip_checksum=1
            fi
        fi
    elif command -v wget >/dev/null 2>&1; then
        if ! wget -q -O "$archive_name" "$url"; then
            log_error "Download failed"
            cd - > /dev/null || cd "$HOME"
            rm -rf "$tmp_dir"
            return 1
        fi
        if [ -z "$skip_checksum" ]; then
            if ! wget -q -O "checksums.txt" "$checksums_url"; then
                log_warning "Failed to download checksums, skipping verification"
                skip_checksum=1
            fi
        fi
    fi

    if [ -z "$skip_checksum" ]; then
        verify_checksum "$tmp_dir/$archive_name" "$tmp_dir/checksums.txt"
    fi

    log_info "Extracting archive..."
    if [ "$ext" = "tar.gz" ]; then
        if ! tar -xzf "$archive_name"; then
            log_error "Failed to extract archive"
            rm -rf "$tmp_dir"
            return 1
        fi
    else
        if ! command -v unzip >/dev/null 2>&1; then
            log_error "unzip required but not found"
            rm -rf "$tmp_dir"
            return 1
        fi
        if ! unzip -q "$archive_name"; then
            log_error "Failed to extract archive"
            rm -rf "$tmp_dir"
            return 1
        fi
    fi

    local install_dir
    if [[ -w /usr/local/bin ]]; then
        install_dir="/usr/local/bin"
    else
        install_dir="$HOME/.local/bin"
        mkdir -p "$install_dir"
    fi

    log_info "Installing to $install_dir..."
    if [[ -w "$install_dir" ]]; then
        mv "$binary" "$install_dir/"
        chmod +x "$install_dir/$binary"
    else
        sudo mv "$binary" "$install_dir/"
        sudo chmod +x "$install_dir/$binary"
    fi

    resign_for_macos "$install_dir/$binary"

    LAST_INSTALL_PATH="$install_dir/$binary"
    log_success "aw installed to $install_dir/$binary"

    if [[ ":$PATH:" != *":$install_dir:"* ]]; then
        log_warning "$install_dir is not in your PATH"
        echo ""
        echo "Add this to your shell profile (~/.bashrc, ~/.zshrc, etc.):"
        echo "  export PATH=\"\$PATH:$install_dir\""
        echo ""
    fi

    cd - > /dev/null || cd "$HOME"
    rm -rf "$tmp_dir"
    return 0
}

# Install using go install (fallback)
install_with_go() {
    log_info "Installing aw using 'go install'..."

    if go install github.com/$REPO/cmd/aw@latest; then
        log_success "aw installed successfully via go install"

        local gobin bin_dir
        gobin=$(go env GOBIN 2>/dev/null || true)
        if [ -n "$gobin" ]; then
            bin_dir="$gobin"
        else
            bin_dir="$(go env GOPATH)/bin"
        fi
        LAST_INSTALL_PATH="$bin_dir/aw"

        resign_for_macos "$bin_dir/aw"

        if [[ ":$PATH:" != *":$bin_dir:"* ]]; then
            log_warning "$bin_dir is not in your PATH"
            echo ""
            echo "Add this to your shell profile (~/.bashrc, ~/.zshrc, etc.):"
            echo "  export PATH=\"\$PATH:$bin_dir\""
            echo ""
        fi

        return 0
    else
        log_error "go install failed"
        return 1
    fi
}

# Check if Go is installed and meets minimum version
check_go() {
    if command -v go >/dev/null 2>&1; then
        local go_version
        go_version=$(go version | awk '{print $3}' | sed 's/go//')

        local major minor
        major=$(echo "$go_version" | cut -d. -f1)
        minor=$(echo "$go_version" | cut -d. -f2)

        if [ "$major" -eq 1 ] && [ "$minor" -lt 21 ]; then
            log_error "Go 1.21 or later is required (found: $go_version)"
            return 1
        fi

        return 0
    else
        return 1
    fi
}

# Main installation flow
main() {
    echo ""
    echo "⚡ aw (aweb CLI) Installer"
    echo ""

    log_info "Detecting platform..."
    local platform
    platform=$(detect_platform)
    log_info "Platform: $platform"

    # Try downloading from GitHub releases first
    if install_from_release "$platform"; then
        verify_installation
        exit 0
    fi

    log_warning "Failed to install from releases, trying alternative methods..."

    # Try go install as fallback
    if check_go; then
        if install_with_go; then
            verify_installation
            exit 0
        fi
    fi

    # All methods failed
    log_error "Installation failed"
    echo ""
    echo "Manual installation:"
    echo "  1. Download from https://github.com/$REPO/releases/latest"
    echo "  2. Extract and move 'aw' to your PATH"
    echo ""
    echo "Or install with Go:"
    echo "  1. Install Go from https://go.dev/dl/"
    echo "  2. Run: go install github.com/$REPO/cmd/aw@latest"
    echo ""
    exit 1
}

main "$@"
