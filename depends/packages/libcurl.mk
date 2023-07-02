package=libcurl
$(package)_version=7.78.0
$(package)_dependencies=openssl
$(package)_download_path=https://curl.haxx.se/download
$(package)_file_name=curl-$($(package)_version).tar.xz
$(package)_sha256_hash=be42766d5664a739c3974ee3dfbbcbe978a4ccb1fe628bb1d9b59ac79e445fb5
$(package)_config_opts_linux=--disable-shared --enable-static --prefix=$(host_prefix) --host=$(HOST) --with-openssl