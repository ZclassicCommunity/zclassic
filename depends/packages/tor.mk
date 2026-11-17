package=tor
# Same Tor source identity as Z23 (vendor/tor submodule pin, fork
# RhettCreighton/tor). The source is the GitHub archive of that exact commit;
# see doc/tor-provenance.md for the commit, archive hash, licences and policy.
$(package)_commit=f4e28103c0eb9016e0b500d02486b7a59d20ee5d
$(package)_version=0.4.9.2-alpha-dev.f4e28103
$(package)_download_path=https://github.com/RhettCreighton/tor/archive
$(package)_download_file=$($(package)_commit).tar.gz
$(package)_file_name=$(package)-$($(package)_commit).tar.gz
$(package)_sha256_hash=72c187cd6228cfde5a8befd299899db24ae857c0c565dbebf92261933cae06a7
$(package)_dependencies=openssl libevent zlib

# The archive carries no generated configure script, so autoconf, automake and
# libtool are needed on the build machine (the same requirement as Z23
# tools/scripts/build_tor_full.sh).
# Carry patches on the pinned fork (doc/tor-provenance.md lists and explains
# each). Applied in order, before autogen.sh; the same on every host.
$(package)_patches=0001-dynhost-stream-shutdown.patch
$(package)_patches+=0002-dynhost-set-enabled.patch
$(package)_patches+=0003-dynhost-free-reassembly-buf.patch
$(package)_patches+=0004-dynhost-clamp-external-handler-length.patch

define $(package)_preprocess_cmds
  patch -p1 < $($(package)_patch_dir)/0001-dynhost-stream-shutdown.patch && \
  patch -p1 < $($(package)_patch_dir)/0002-dynhost-set-enabled.patch && \
  patch -p1 < $($(package)_patch_dir)/0003-dynhost-free-reassembly-buf.patch && \
  patch -p1 < $($(package)_patch_dir)/0004-dynhost-clamp-external-handler-length.patch && \
  ./autogen.sh
endef

define $(package)_set_vars
  # Configure policy copied from Z23 tools/scripts/build_tor_full.sh, plus the
  # client/onion-service-only trims noted in doc/tor-provenance.md. No
  # --enable-gpl: that would build the LGPL/GPL Equi-X proof-of-work code.
  $(package)_config_opts=ac_cv_func_backtrace=no ac_cv_lib_cap_cap_init=no ac_cv_func_cap_set_proc=no
  $(package)_config_opts+=--with-openssl-dir=$(host_prefix) --with-libevent-dir=$(host_prefix) --with-zlib-dir=$(host_prefix)
  $(package)_config_opts+=--enable-static-openssl --enable-static-libevent --enable-static-zlib
  $(package)_config_opts+=--disable-asciidoc --disable-manpage --disable-html-manual
  $(package)_config_opts+=--disable-systemd --disable-seccomp --disable-lzma --disable-zstd --disable-libscrypt
  $(package)_config_opts+=--disable-unittests --disable-system-torrc
  $(package)_config_opts+=--disable-module-relay --disable-module-dirauth
  $(package)_config_opts+=--enable-pic
  $(package)_config_opts_mingw32=--disable-tool-name-check LIBS="-liphlpapi -lbcrypt -lws2_32"
endef

define $(package)_config_cmds
  $($(package)_autoconf)
endef

# Only the static archives are built; the tor executable is not needed.
define $(package)_build_cmds
  $(MAKE) libtor.a src/ext/ed25519/donna/libed25519_donna.a src/ext/ed25519/ref10/libed25519_ref10.a src/ext/keccak-tiny/libkeccak-tiny.a
endef

define $(package)_stage_cmds
  mkdir -p $($(package)_staging_dir)$(host_prefix)/lib $($(package)_staging_dir)$(host_prefix)/include && \
  cp libtor.a src/ext/ed25519/donna/libed25519_donna.a src/ext/ed25519/ref10/libed25519_ref10.a src/ext/keccak-tiny/libkeccak-tiny.a $($(package)_staging_dir)$(host_prefix)/lib/ && \
  cp src/feature/api/tor_api.h $($(package)_staging_dir)$(host_prefix)/include/
endef
