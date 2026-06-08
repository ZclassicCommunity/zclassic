package=zlib
$(package)_version=1.3.1
$(package)_download_path=https://zlib.net/fossils
$(package)_file_name=zlib-$($(package)_version).tar.gz
$(package)_sha256_hash=9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23

# zlib's configure is hand-rolled (not autotools) and ignores --host, so drive it per target.
define $(package)_config_cmds
  CHOST=$(host) CC="$($(package)_cc)" AR="$($(package)_ar)" RANLIB="$($(package)_ranlib)" \
  CFLAGS="$($(package)_cflags) $($(package)_cppflags) -fPIC" ./configure --static --prefix=$(host_prefix)
endef

define $(package)_build_cmds
  $(MAKE) libz.a
endef

define $(package)_stage_cmds
  $(MAKE) install DESTDIR=$($(package)_staging_dir)
endef

# mingw32: ./configure can't cross -> use win32/Makefile.gcc
define $(package)_config_cmds_mingw32
  true
endef

define $(package)_build_cmds_mingw32
  $(MAKE) -f win32/Makefile.gcc PREFIX=$(host)- CC=$(host)-gcc AR=$(host)-ar RANLIB=$(host)-ranlib CFLAGS="-fPIC -O2" libz.a
endef

define $(package)_stage_cmds_mingw32
  $(MAKE) -f win32/Makefile.gcc PREFIX=$(host)- \
    BINARY_PATH=$($(package)_staging_dir)$(host_prefix)/bin \
    INCLUDE_PATH=$($(package)_staging_dir)$(host_prefix)/include \
    LIBRARY_PATH=$($(package)_staging_dir)$(host_prefix)/lib install
endef
