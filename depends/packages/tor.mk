package=tor
$(package)_version=73bd405
# Vendored fork tree (RhettCreighton/tor, dynhost branch @73bd405, Tor 0.4.9.x).
# The tarball is checked in at depends/sources/tor-$(version).tar.gz (no download_path:
# funcs.mk skips the download when the source file already exists). Reproduce with:
#   git -C <tor-dynhost> archive --format=tar --prefix=tor-73bd405/ 73bd405 | gzip -n
$(package)_file_name=tor-$($(package)_version).tar.gz
$(package)_sha256_hash=178fb8242d5a1066c3535f1328d8b5ef1e4578e318a8e622d6a6732144fa2517
$(package)_dependencies=openssl libevent zlib

define $(package)_set_vars
  $(package)_config_opts=--disable-shared --enable-pic
  $(package)_config_opts+=--with-openssl-dir=$(host_prefix) --with-libevent-dir=$(host_prefix) --with-zlib-dir=$(host_prefix)
  $(package)_config_opts+=--enable-static-openssl --enable-static-libevent --enable-static-zlib
  $(package)_config_opts+=--disable-unittests --disable-asciidoc --disable-manpage --disable-html-manual
  $(package)_config_opts+=--disable-system-torrc --disable-systemd --disable-seccomp --disable-lzma --disable-zstd
  $(package)_config_opts+=--disable-module-relay --disable-module-dirauth --disable-tool-name-check
  # Do NOT pass --enable-gpl: keeps the GPL EQUIX/PoW module OUT of libtor.a
  # (license conflict with the MIT/Apache daemon; verified absent in the build script).
endef

define $(package)_preprocess_cmds
  ./autogen.sh
endef

define $(package)_config_cmds
  $($(package)_autoconf)
endef

define $(package)_build_cmds
  $(MAKE) libtor.a
endef

define $(package)_stage_cmds
  mkdir -p $($(package)_staging_dir)$(host_prefix)/lib $($(package)_staging_dir)$(host_prefix)/include && \
  cp libtor.a $($(package)_staging_dir)$(host_prefix)/lib/ && \
  cp src/feature/api/tor_api.h $($(package)_staging_dir)$(host_prefix)/include/
endef

# Re-index the staged archive (no-op / native ranlib on a native build).
define $(package)_postprocess_cmds
  $(host)-ranlib lib/libtor.a 2>/dev/null || ranlib lib/libtor.a
endef
