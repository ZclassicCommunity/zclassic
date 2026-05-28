#!/usr/bin/env bash

set -eu -o pipefail

# ZClassic Dependency Installation Script
# Installs required system packages for building zclassicd.
#
# Usage:
#   ./zcutil/install-deps.sh           # native (Linux) build deps
#   ./zcutil/install-deps.sh --mingw   # also install the Win64 cross toolchain

WITH_MINGW=0
for arg in "$@"; do
    case "$arg" in
        --mingw) WITH_MINGW=1 ;;
        *) echo "unknown option: $arg" >&2; exit 1 ;;
    esac
done

echo "ZClassic Build Dependencies Installer"
echo "======================================"
echo ""

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "Cannot detect OS. This script supports Ubuntu/Debian."
    exit 1
fi

# Check if running as root or with sudo
if [ "$EUID" -eq 0 ]; then
    SUDO=""
else
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
        echo "This script will use sudo to install system packages."
        echo ""
    else
        echo "Error: This script needs to install system packages but sudo is not available."
        echo "Please run as root or install sudo."
        exit 1
    fi
fi

install_ubuntu_debian() {
    echo "Installing dependencies for Ubuntu/Debian..."
    echo ""

    # Update package list
    $SUDO apt-get update

    # Required build tools
    PACKAGES=(
        # Build essentials
        build-essential
        pkg-config
        libc6-dev
        m4
        g++-multilib
        autoconf
        libtool
        automake

        # Required libraries
        libgmp-dev          # GNU Multiple Precision library
        libdb++-dev         # Berkeley DB (for wallet support)
        libsodium-dev       # Cryptography library

        # Additional utilities
        git
        python3
        wget
        curl

        # Optional but recommended
        zlib1g-dev
        libssl-dev
        libevent-dev
    )

    echo "Installing packages: ${PACKAGES[*]}"
    echo ""

    $SUDO apt-get install -y "${PACKAGES[@]}"

    echo ""
    echo "✓ All dependencies installed successfully!"
}

install_mingw_toolchain() {
    echo ""
    echo "Installing the mingw-w64 (Win64) cross toolchain..."
    echo ""

    # Base packages pull gcc/g++/binutils/headers and both thread models.
    $SUDO apt-get install -y \
        g++-mingw-w64-x86-64 \
        gcc-mingw-w64-x86-64 \
        binutils-mingw-w64-x86-64 \
        mingw-w64-x86-64-dev \
        mingw-w64-tools

    # The C++ code needs the POSIX thread model (std::thread / std::mutex).
    $SUDO update-alternatives --set x86_64-w64-mingw32-gcc /usr/bin/x86_64-w64-mingw32-gcc-posix || true
    $SUDO update-alternatives --set x86_64-w64-mingw32-g++ /usr/bin/x86_64-w64-mingw32-g++-posix || true

    echo ""
    echo "✓ mingw-w64 toolchain installed ($(x86_64-w64-mingw32-g++ -dumpversion 2>/dev/null), thread model: $(x86_64-w64-mingw32-g++ -v 2>&1 | sed -n 's/^Thread model: //p'))"
}

case "$OS" in
    ubuntu|debian|linuxmint|pop)
        install_ubuntu_debian
        [ "$WITH_MINGW" -eq 1 ] && install_mingw_toolchain
        ;;
    *)
        echo "Unsupported OS: $OS"
        echo "This script currently supports Ubuntu and Debian-based distributions."
        echo ""
        echo "Required packages:"
        echo "  - build-essential, autoconf, libtool, automake"
        echo "  - libgmp-dev, libdb++-dev, libsodium-dev"
        echo "  - (Win64 cross) g++-mingw-w64-x86-64-posix, mingw-w64-x86-64-dev"
        echo ""
        echo "Please install these manually for your distribution."
        exit 1
        ;;
esac

echo ""
echo "You can now build ZClassic by running:"
echo "  ./zcutil/build-release.sh linux -j\$(nproc)      # stripped Linux binaries"
if [ "$WITH_MINGW" -eq 1 ]; then
    echo "  ./zcutil/build-release.sh win64 -j\$(nproc)      # stripped Win64 .exe binaries"
fi
