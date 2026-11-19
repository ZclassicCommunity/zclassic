package=zlib
$(package)_version=1.3.1
$(package)_download_path=https://github.com/madler/zlib/releases/download/v$($(package)_version)
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23

# zlib is needed only by the embedded Tor (packages/tor.mk). It is built as a
# static library with zlib own configure script, which is not autoconf: it
# takes CC/AR/RANLIB from the environment and CHOST to select the target.
define $(package)_set_vars
  $(package)_config_env=CC="$($(package)_cc)" AR="$($(package)_ar)" RANLIB="$($(package)_ranlib)" CFLAGS="$($(package)_cflags) $($(package)_cppflags) -fPIC" CHOST="$(host)"
endef

define $(package)_config_cmds
  $($(package)_config_env) ./configure --static --prefix=$(host_prefix)
endef

define $(package)_build_cmds
  $(MAKE) libz.a
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef

define $(package)_postprocess_cmds
  rm -rf share
endef
