package=zstd
$(package)_version=1.5.6
$(package)_download_path=https://github.com/facebook/zstd/releases/download/v$($(package)_version)
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=8c29e06cf42aacc1eafc4077ae2ec6c6fcb96a626157e0593d5e82a34fd403c1
$(package)_build_subdir=out

define $(package)_preprocess_cmds
  mkdir -p out
endef

define $(package)_config_cmds
  cmake -DCMAKE_INSTALL_PREFIX=$(host_prefix) \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_OSX_ARCHITECTURES=arm64 \
        -DZSTD_BUILD_STATIC=ON \
        -DZSTD_BUILD_SHARED=OFF \
        -DZSTD_BUILD_PROGRAMS=OFF \
        -DZSTD_BUILD_TESTS=OFF \
        ../build/cmake
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef
