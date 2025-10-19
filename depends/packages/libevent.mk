package=libevent
$(package)_version=2.1.8
$(package)_download_path=https://github.com/libevent/libevent/releases/download/release-$($(package)_version)-stable
$(package)_file_name=$(package)-$($(package)_version)-stable.tar.gz
$(package)_sha256_hash=965cc5a8bb46ce4199a47e9b2c9e1cae3b137e8356ffdad6d94d3b9069b71dc2
$(package)_patches=fix-linux-arc4random.patch

define $(package)_preprocess_cmds
  patch -p1 < $($(package)_patch_dir)/fix-linux-arc4random.patch
endef

define $(package)_set_vars
  $(package)_cflags_darwin=$(shell command -v xcrun >/dev/null 2>&1 && echo "-isysroot$$(xcrun --show-sdk-path)")
  $(package)_cxxflags_darwin=$(shell command -v xcrun >/dev/null 2>&1 && echo "-isysroot$$(xcrun --show-sdk-path)")
  $(package)_config_opts=--disable-shared --disable-openssl --disable-libevent-regress
  $(package)_config_opts_release=--disable-debug-mode
  $(package)_config_opts_linux=--with-pic
endef

define $(package)_config_cmds
  $($(package)_autoconf)
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef

define $(package)_postprocess_cmds
endef
