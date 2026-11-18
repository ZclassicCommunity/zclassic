zcash_packages := libsodium
packages := boost openssl libevent zeromq $(zcash_packages) googletest
native_packages := native_ccache

wallet_packages=bdb

# Embedded Tor (zlib + tor, see packages/tor.mk) is built by default for linux,
# mingw32 and darwin hosts, so the release binary can offer -embeddedtor (off at
# run time unless asked). Leave it out: make -C depends NO_EMBEDDED_TOR=1 ...
# (WITH_EMBEDDED_TOR=0 is the same). Other hosts get it only with WITH_EMBEDDED_TOR=1.
ifeq ($(NO_EMBEDDED_TOR)$(filter 0,$(WITH_EMBEDDED_TOR)),)
ifneq ($(filter linux darwin mingw32,$(host_os))$(filter-out 0,$(WITH_EMBEDDED_TOR)),)
packages += zlib tor
endif
endif
