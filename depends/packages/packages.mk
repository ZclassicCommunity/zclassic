proton_packages := proton
zcash_packages := libgmp libsodium
packages := boost openssl libevent zeromq $(zcash_packages) googletest libcurl
native_packages := native_clang native_ccache native_cmake native_cxxbridge native_zstd native_rust

wallet_packages=bdb

ifneq (,$(wildcard /etc/arch-release))
native_packages += native_libtinfo
endif

wallet_packages=bdb

$(host_arch)_$(host_os)_native_packages += native_b2

ifneq ($(build_os),darwin)
darwin_native_packages=native_cctools
endif


# We use a complete SDK for Darwin, which includes libc++.
ifneq ($(host_os),darwin)
packages += libcxx
endif
