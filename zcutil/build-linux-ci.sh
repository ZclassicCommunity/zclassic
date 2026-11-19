#!/bin/bash

export LC_ALL=C
set -eu
set -o pipefail

#KNOBS########
PKG="zclassicd"
VER="v2.1.1-5"  # legacy label only (directory and archive name), not the node version; see doc/building-daemon-from-source.md
##############

mkdir -p depends/${PKG}-${VER}/bin
mkdir -p depends/bin

CONFIGURE_FLAGS="--disable-tests --disable-man" ./zcutil/build.sh

cp src/zclassicd depends/${PKG}-${VER}/bin
cp src/zclassic-cli depends/${PKG}-${VER}/bin
cp src/zclassic-tx depends/${PKG}-${VER}/bin
cp zcutil/zsync.sh depends/${PKG}-${VER}/bin
chmod a+x depends/${PKG}-${VER}/bin/*

tar zcvf ${PKG}-${VER}.tar.gz depends/${PKG}-${VER}/

mv ${PKG}-${VER}.tar.gz depends/bin/

exit 0


