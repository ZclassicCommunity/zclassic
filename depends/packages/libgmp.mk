package=libgmp
$(package)_version=6.3.0
# gmplib.org throttles/blocks datacenter IPs (CI runners time out on it), and
# the depends fallback mirror doesn't carry this version. ftp.gnu.org serves
# the identical canonical release (sha256 unchanged) and is reliable from CI.
$(package)_download_path=https://ftp.gnu.org/gnu/gmp/
$(package)_file_name=gmp-$($(package)_version).tar.bz2
$(package)_sha256_hash=ac28211a7cfb609bae2e2c8d6058d66c8fe96434f740cf6fe2e47b000d1c20cb
$(package)_dependencies=
$(package)_config_opts=--enable-cxx --disable-shared
$(package)_config_opts_arm_darwin=--disable-assembly

define $(package)_config_cmds
  $($(package)_autoconf) --host=$(host) --build=$(build)
endef

define $(package)_build_cmds
  $(MAKE) CPPFLAGS='-fPIC'
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install ; echo '=== staging find for $(package):' ; find $($(package)_staging_dir)
endef
