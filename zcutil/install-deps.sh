#!/usr/bin/env bash

set -eu -o pipefail

# ZClassic Dependency Installation Script
# Installs required system packages for building zclassicd

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

case "$OS" in
    ubuntu|debian|linuxmint|pop)
        install_ubuntu_debian
        ;;
    *)
        echo "Unsupported OS: $OS"
        echo "This script currently supports Ubuntu and Debian-based distributions."
        echo ""
        echo "Required packages:"
        echo "  - build-essential, autoconf, libtool, automake"
        echo "  - libgmp-dev, libdb++-dev, libsodium-dev"
        echo ""
        echo "Please install these manually for your distribution."
        exit 1
        ;;
esac

echo ""
echo "You can now build ZClassic by running:"
echo "  ./zcutil/build.sh -j\$(nproc)"
