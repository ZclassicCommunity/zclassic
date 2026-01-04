package=brotli
$(package)_version=1.1.0
$(package)_download_path=https://github.com/google/brotli/archive/refs/tags
$(package)_file_name=v$($(package)_version).tar.gz
$(package)_sha256_hash=e720a6ca29428b803f4ad165371771f5398faba397edf6778837a18599ea13ff
$(package)_build_subdir=build

define $(package)_preprocess_cmds
  mkdir -p build
endef

define $(package)_config_cmds
  cmake -DCMAKE_INSTALL_PREFIX=$(host_prefix) \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_OSX_ARCHITECTURES=arm64 \
        -DBUILD_SHARED_LIBS=OFF \
        -DBROTLI_DISABLE_TESTS=ON \
        ..
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef
