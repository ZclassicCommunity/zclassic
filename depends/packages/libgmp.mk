package=libgmp
$(package)_version=6.3.0
$(package)_download_path=https://gmplib.org/download/gmp/
$(package)_file_name=gmp-$($(package)_version).tar.bz2
$(package)_sha256_hash=ac28211a7cfb609bae2e2c8d6058d66c8fe96434f740cf6fe2e47b000d1c20cb
$(package)_dependencies=
$(package)_config_opts=--enable-cxx --disable-shared
$(package)_config_opts_arm_darwin=--disable-assembly

# to build on Arch Manjaro (Rhett Creighton commit https://github.com/ZclassicCommunity/zclassic/commit/3ebf6e0367443517a02fb4950bda9ab9b14edc0e)
define $(package)_preprocess_cmds
  sed -i.orig 's/void g(){}/void g(int a, void* b, unsigned long long c, void* d, void* e, int f){}/g' configure && \
  sed -i 's/void h(){}/void h(void){}/g' configure
endef
##

define $(package)_config_cmds
  $($(package)_autoconf) --host=$(host) --build=$(build)
endef

define $(package)_build_cmds
  $(MAKE) CPPFLAGS='-fPIC'
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install ; echo '=== staging find for $(package):' ; find $($(package)_staging_dir)
endef
