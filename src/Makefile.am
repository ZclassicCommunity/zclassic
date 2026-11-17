DIST_SUBDIRS = secp256k1 univalue

AM_LDFLAGS = $(PTHREAD_CFLAGS) $(LIBTOOL_LDFLAGS) $(SAN_LDFLAGS) $(HARDENED_LDFLAGS)
AM_CXXFLAGS = $(SAN_CXXFLAGS) $(HARDENED_CXXFLAGS) $(ERROR_CXXFLAGS)
# c23/compat comes FIRST: #include "librustzcash.h" must resolve to the C23 shim
# header (src/c23/compat/librustzcash.h), never to a Rust header in a depends prefix.
AM_CPPFLAGS = -I$(srcdir)/c23/compat $(HARDENED_CPPFLAGS) -DBOOST_BIND_GLOBAL_PLACEHOLDERS
EXTRA_LIBRARIES =

if EMBEDDED_LEVELDB
LEVELDB_CPPFLAGS += -I$(srcdir)/leveldb/include
LEVELDB_CPPFLAGS += -I$(srcdir)/leveldb/helpers/memenv
LIBLEVELDB += $(builddir)/leveldb/libleveldb.a
LIBMEMENV  += $(builddir)/leveldb/libmemenv.a

# NOTE: This dependency is not strictly necessary, but without it make may try to build both in parallel, which breaks the LevelDB build system in a race
$(LIBLEVELDB): $(LIBMEMENV)

$(LIBLEVELDB) $(LIBMEMENV):
	@echo "Building LevelDB ..." && $(MAKE) -C $(@D) $(@F) CXX="$(CXX)" \
	  CC="$(CC)" PLATFORM=$(TARGET_OS) AR="$(AR)" $(LEVELDB_TARGET_FLAGS) \
          OPT="$(AM_CXXFLAGS) $(PIE_FLAGS) $(CXXFLAGS) $(AM_CPPFLAGS) $(CPPFLAGS) -D__STDC_LIMIT_MACROS"
endif

BITCOIN_CONFIG_INCLUDES=-I$(builddir)/config
BITCOIN_INCLUDES=-I$(builddir) -I$(builddir)/obj $(BDB_CPPFLAGS) $(BOOST_CPPFLAGS) $(LEVELDB_CPPFLAGS) $(CRYPTO_CFLAGS) $(SSL_CFLAGS)

BITCOIN_INCLUDES += -I$(srcdir)/secp256k1/include
BITCOIN_INCLUDES += -I$(srcdir)/snark
BITCOIN_INCLUDES += -I$(srcdir)/snark/libsnark
BITCOIN_INCLUDES += -I$(srcdir)/univalue/include

LIBBITCOIN_SERVER=libbitcoin_server.a
LIBBITCOIN_COMMON=libbitcoin_common.a
LIBBITCOIN_CLI=libbitcoin_cli.a
LIBBITCOIN_UTIL=libbitcoin_util.a
# SHA-256 backend of CSHA256: vendored Z23 C23 with run-time CPU dispatch.
# crypto/sha256.cpp calls it, so it always travels right behind libbitcoin_crypto.
LIBZCL_C23_HASH=libzcl_c23_hash.a
LIBBITCOIN_CRYPTO=crypto/libbitcoin_crypto.a $(LIBZCL_C23_HASH)
LIBSECP256K1=secp256k1/libsecp256k1.la
LIBSNARK=snark/libsnark.a
LIBUNIVALUE=univalue/libunivalue.la
LIBZCASH=libzcash.a
# The C23 crypto core that replaces librustzcash (see src/c23/README.md), then the
# C++ seam it calls back into (logging, network id). Always list them together and
# in this order, after every library that calls librustzcash_* and before
# -lsodium -lcrypto.
LIBZCL_C23=libzcl_c23.a libzcl_c23_seam.a

# The daemon's own C support code, a separate archive from the vendored C23 core:
# owner-only key files, and (with --with-embedded-tor) the embedded Tor launcher.
# Programs that link $(LIBBITCOIN_SERVER) need $(ZCL_TOR_LIBS) after it: with
# embedded Tor, also libtor and the archives it uses.
LIBZCL_TOR=libzcl_tor.a
ZCL_TOR_LIBS = $(LIBZCL_TOR)
if ENABLE_EMBEDDED_TOR
ZCL_TOR_LIBS += $(TOR_LIBS) $(SSL_LIBS) $(CRYPTO_LIBS) $(EVENT_PTHREADS_LIBS) $(EVENT_LIBS) $(TOR_SYSTEM_LIBS)
endif

if ENABLE_ZMQ
LIBBITCOIN_ZMQ=libbitcoin_zmq.a
endif
if ENABLE_PROTON
LIBBITCOIN_PROTON=libbitcoin_proton.a
endif
if BUILD_BITCOIN_LIBS
LIBZCASH_CONSENSUS=libzcashconsensus.la
endif
if ENABLE_WALLET
# libzcl_tokenguard.a is part of the wallet, not an option: every target that
# links the wallet gets the token guard (see src/c23/services/README.md). It
# must stay listed right after libbitcoin_wallet.a, which calls into it.
LIBBITCOIN_WALLET=libbitcoin_wallet.a libzcl_tokenguard.a
endif

$(LIBSECP256K1): $(wildcard secp256k1/src/*) $(wildcard secp256k1/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

# libsnark's standalone makefile compiles with CXXFLAGS alone. Carry the same
# preprocessor ABI switches (notably _GLIBCXX_DEBUG) as its callers.
LIBSNARK_CXXFLAGS = $(CPPFLAGS) $(CXXFLAGS) $(AM_CXXFLAGS) $(PIC_FLAGS) -DBINARY_OUTPUT -DNO_PT_COMPRESSION=1 -fstack-protector-all
LIBSNARK_CONFIG_FLAGS = CURVE=ALT_BN128 NO_PROCPS=1 NO_DOCS=1 STATIC=1 NO_SUPERCOP=1 FEATUREFLAGS=-DMONTGOMERY_OUTPUT NO_COPY_DEPINST=1 NO_COMPILE_LIBGTEST=1
if HAVE_OPENMP
LIBSNARK_CONFIG_FLAGS += MULTICORE=1
endif
if TARGET_DARWIN
LIBSNARK_CONFIG_FLAGS += PLATFORM=darwin
endif

$(LIBSNARK): $(wildcard snark/src/*)
	$(AM_V_at) CC="$(CC)" CXX="$(CXX)" AR="$(AR)" CXXFLAGS="$(LIBSNARK_CXXFLAGS)" $(MAKE) $(AM_MAKEFLAGS) -C snark/ DEPINST="$(LIBSNARK_DEPINST)" $(LIBSNARK_CONFIG_FLAGS) OPTFLAGS="-O3" NO_GTEST=1 CURVE=ALT_BN128 FEATUREFLAGS="-DUSE_ASM -DMONTGOMERY_OUTPUT -DNO_PROCPS" lib

libsnark-tests: $(wildcard snark/src/*)
	$(AM_V_at) CC="$(CC)" CXX="$(CXX)" AR="$(AR)" CXXFLAGS="$(LIBSNARK_CXXFLAGS)" $(MAKE) $(AM_MAKEFLAGS) -C snark/ check DEPINST="$(LIBSNARK_DEPINST)" $(LIBSNARK_CONFIG_FLAGS) OPTFLAGS="-O3"

$(LIBUNIVALUE): $(wildcard univalue/lib/*) $(wildcard univalue/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

# Make is not made aware of per-object dependencies to avoid limiting building parallelization
# But to build the less dependent modules first, we manually select their order here:
EXTRA_LIBRARIES += \
  $(LIBBITCOIN_CRYPTO) \
  $(LIBBITCOIN_UTIL) \
  $(LIBBITCOIN_COMMON) \
  $(LIBBITCOIN_SERVER) \
  $(LIBBITCOIN_CLI) \
  $(LIBBITCOIN_WALLET) \
  $(LIBBITCOIN_ZMQ) \
  $(LIBBITCOIN_PROTON) \
  $(LIBZCASH) \
  $(LIBZCL_C23) \
  $(LIBZCL_TOR)

lib_LTLIBRARIES = $(LIBZCASH_CONSENSUS)

bin_PROGRAMS =
noinst_PROGRAMS =
TESTS =

if BUILD_BITCOIND
  bin_PROGRAMS += zclassicd
endif

if BUILD_BITCOIN_UTILS
  bin_PROGRAMS += zclassic-cli zclassic-tx
endif

LIBZCASH_H = \
  zcash/IncrementalMerkleTree.hpp \
  zcash/NoteEncryption.hpp \
  zcash/Address.hpp \
  zcash/JoinSplit.hpp \
  zcash/Note.hpp \
  zcash/prf.h \
  zcash/Proof.hpp \
  zcash/util.h \
  zcash/Zcash.h \
  zcash/zip32.h

.PHONY: FORCE collate-libsnark check-symbols check-security check-c23-vendor check-c23-no-rust
# bitcoin core #
BITCOIN_CORE_H = \
  addrman.h \
  amount.h \
  amqp/amqpabstractnotifier.h \
  amqp/amqpconfig.h \
  amqp/amqpnotificationinterface.h \
  amqp/amqppublishnotifier.h \
  amqp/amqpsender.h \
  arith_uint256.h \
  asyncrpcoperation.h \
  asyncrpcqueue.h \
  base58.h \
  bech32.h \
  bootstrap.h \
  bootstrapvalidation.h \
  bloom.h \
  chain.h \
  parkedblockindex.h \
  chainparams.h \
  chainparamsbase.h \
  chainparamsseeds.h \
  checkpoints.h \
  checkqueue.h \
  clientversion.h \
  coincontrol.h \
  coins.h \
  compat.h \
  compat/byteswap.h \
  compat/endian.h \
  compat/sanity.h \
  compressor.h \
  consensus/consensus.h \
  consensus/params.h \
  consensus/upgrades.h \
  consensus/validation.h \
  core_io.h \
  crypto/sha3.h \
  core_memusage.h \
  deprecation.h \
  embeddedtor.h \
  hash.h \
  httprpc.h \
  httpserver.h \
  init.h \
  startuptimer.h \
  key.h \
  key_io.h \
  keystore.h \
  dbwrapper.h \
  limitedmap.h \
  main.h \
  mapport.h \
  memusage.h \
  merkleblock.h \
  metrics.h \
  miner.h \
  mruset.h \
  net.h \
  netbase.h \
  noui.h \
  policy/fees.h \
  pow.h \
  equihashmemo.h \
  prevector.h \
  primitives/block.h \
  primitives/transaction.h \
  protocol.h \
  pubkey.h \
  random.h \
  reverselock.h \
  rpc/client.h \
  rpc/protocol.h \
  rpc/server.h \
  rpc/register.h \
  scheduler.h \
  script/sighashtype.h \
  script/interpreter.h \
  script/script.h \
  script/script_error.h \
  script/sigcache.h \
  script/sign.h \
  script/standard.h \
  script/script_flags.h \
  script/sigencoding.cpp \
  script/sigencoding.h \
  serialize.h \
  streams.h \
  support/allocators/secure.h \
  support/allocators/zeroafterfree.h \
  support/cleanse.h \
  support/events.h \
  support/pagelocker.h \
  sync.h \
  threadsafety.h \
  timedata.h \
  tinyformat.h \
  torcontrol.h \
  transaction_builder.h \
  txdb.h \
  txmempool.h \
  ui_interface.h \
  uint256.h \
  uint252.h \
  undo.h \
  util.h \
  utilmoneystr.h \
  utilstrencodings.h \
  utiltest.h \
  utiltime.h \
  validationinterface.h \
  version.h \
  wallet/asyncrpcoperation_mergetoaddress.h \
  wallet/asyncrpcoperation_sendmany.h \
  wallet/asyncrpcoperation_shieldcoinbase.h \
  wallet/crypter.h \
  wallet/db.h \
  wallet/paymentdisclosure.h \
  wallet/paymentdisclosuredb.h \
  wallet/rpcwallet.h \
  wallet/tokenguard.h \
  wallet/wallet.h \
  wallet/wallet_ismine.h \
  wallet/walletdb.h \
  zmq/zmqabstractnotifier.h \
  zmq/zmqconfig.h\
  zmq/zmqnotificationinterface.h \
  zmq/zmqpublishnotifier.h


obj/build.h: FORCE
	@$(MKDIR_P) $(builddir)/obj
	@$(top_srcdir)/share/genbuild.sh $(abs_top_builddir)/src/obj/build.h \
	  $(abs_top_srcdir)
libbitcoin_util_a-clientversion.$(OBJEXT): obj/build.h

# Daemon C support code (not vendored Z23): owner-only key files, and the embedded
# Tor launcher. Every global of the archive is zcl_tor_*; see c23-symbols.stamp.
libzcl_tor_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES) $(EVENT_CFLAGS)
libzcl_tor_a_CFLAGS = $(SAN_CXXFLAGS) $(HARDENED_CXXFLAGS) $(PIE_FLAGS)
libzcl_tor_a_SOURCES = \
  c23/tor/keyfile.c \
  c23/tor/keyfile.h
if ENABLE_EMBEDDED_TOR
libzcl_tor_a_SOURCES += \
  c23/tor/zcl_tor_dispatch.c \
  c23/tor/zcl_tor_embed.c \
  c23/tor/zcl_tor_embed.h \
  c23/tor/zcl_tor_inproc.c \
  c23/tor/zcl_tor_inproc.h \
  c23/tor/zcl_tor_proc.h
if TARGET_WINDOWS
libzcl_tor_a_SOURCES += c23/tor/zcl_tor_proc_win.c
else
libzcl_tor_a_SOURCES += c23/tor/zcl_tor_proc_posix.c
endif
endif

# server: zclassicd
libbitcoin_server_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES) $(EVENT_CFLAGS) $(EVENT_PTHREADS_CFLAGS)
libbitcoin_server_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libbitcoin_server_a_SOURCES = \
  addrman.cpp \
  asyncrpcoperation.cpp \
  asyncrpcqueue.cpp \
  bootstrap.cpp \
  bootstrapvalidation.cpp \
  bloom.cpp \
  chain.cpp \
  checkpoints.cpp \
  deprecation.cpp \
  embeddedtor.cpp \
  equihashmemo.cpp \
  httprpc.cpp \
  httpserver.cpp \
  init.cpp \
  startuptimer.cpp \
  dbwrapper.cpp \
  main.cpp \
  mapport.cpp \
  merkleblock.cpp \
  metrics.cpp \
  miner.cpp \
  net.cpp \
  noui.cpp \
  policy/fees.cpp \
  pow.cpp \
  rest.cpp \
  sha256.cpp \
  rpc/blockchain.cpp \
  rpc/mining.cpp \
  rpc/misc.cpp \
  rpc/net.cpp \
  rpc/rawtransaction.cpp \
  rpc/server.cpp \
  script/sigcache.cpp \
  timedata.cpp \
  torcontrol.cpp \
  txdb.cpp \
  txmempool.cpp \
  validationinterface.cpp \
  $(BITCOIN_CORE_H) \
  $(LIBZCASH_H)

if ENABLE_ZMQ
libbitcoin_zmq_a_CPPFLAGS = $(BITCOIN_INCLUDES) $(ZMQ_CFLAGS)
libbitcoin_zmq_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libbitcoin_zmq_a_SOURCES = \
  zmq/zmqabstractnotifier.cpp \
  zmq/zmqnotificationinterface.cpp \
  zmq/zmqpublishnotifier.cpp
endif

if ENABLE_PROTON
libbitcoin_proton_a_CPPFLAGS = $(BITCOIN_INCLUDES)
libbitcoin_proton_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libbitcoin_proton_a_SOURCES = \
  amqp/amqpabstractnotifier.cpp \
  amqp/amqpnotificationinterface.cpp \
  amqp/amqppublishnotifier.cpp
endif

# wallet: zclassicd, but only linked when wallet enabled
libbitcoin_wallet_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libbitcoin_wallet_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libbitcoin_wallet_a_SOURCES = \
  zcbenchmarks.cpp \
  zcbenchmarks.h \
  wallet/asyncrpcoperation_mergetoaddress.cpp \
  wallet/asyncrpcoperation_sendmany.cpp \
  wallet/asyncrpcoperation_shieldcoinbase.cpp \
  wallet/crypter.cpp \
  wallet/db.cpp \
  wallet/paymentdisclosure.cpp \
  wallet/paymentdisclosuredb.cpp \
  wallet/rpcdisclosure.cpp \
  wallet/rpcdump.cpp \
  wallet/rpcwallet.cpp \
  wallet/tokenguard.cpp \
  wallet/wallet.cpp \
  wallet/wallet_ismine.cpp \
  wallet/walletdb.cpp \
  $(BITCOIN_CORE_H) \
  $(LIBZCASH_H)

# Wallet token guard: Z23's SLP wire parser, vendored verbatim, plus zclassicd
# glue. Plain C, compiled into every wallet build with no feature flag.
#
# The include directories are -iquote, not -I, and belong to this C library
# ONLY. Z23 header names collide with zclassicd's (the vendored slp.c includes
# "primitives/transaction.h"); -iquote is searched before the -I. that automake
# adds, so the glue header wins here, and no C++ target ever sees these
# directories. C++ includes c23/services/glue/zcl_token_guard.h by path.
libzcl_tokenguard_a_SOURCES = \
  c23/services/glue/zcl_token_guard.c \
  c23/services/glue/zcl_token_guard.h \
  c23/services/glue/zcl_tokenguard_symbol_prefix.h \
  c23/services/glue/core/uint256.h \
  c23/services/glue/primitives/transaction.h \
  c23/services/glue/util/log_macros.h \
  c23/services/vendor/contexts/market/modules/zslp/include/zslp/slp.h \
  c23/services/vendor/contexts/market/modules/zslp/src/slp.c \
  c23/services/vendor/core/modules/script/include/script/op_return_push.h \
  c23/services/vendor/engine/modules/overlay/include/overlay/overlay_codec.h \
  c23/services/vendor/engine/modules/overlay/src/overlay_codec.c
libzcl_tokenguard_a_CPPFLAGS = $(HARDENED_CPPFLAGS) $(ZCL_C23_STD_DEFS) \
  -iquote $(srcdir)/c23/services/glue \
  -iquote $(srcdir)/c23/services/vendor/contexts/market/modules/zslp/include \
  -iquote $(srcdir)/c23/services/vendor/engine/modules/overlay/include \
  -iquote $(srcdir)/c23/services/vendor/core/modules/script/include
# The same language level as the C23 crypto core: configure picks -std=c23 when the
# compiler speaks it, else -std=gnu17 (release toolchains: GCC 9, mingw-w64 GCC 13).
# Automake puts $(CFLAGS) after the per-target flags, so any -std= is dropped from it
# for these objects. Every global name of the vendored files is renamed to
# zc23_<name> by the force-included prefix header (proved by c23-symbols.stamp).
# No -march / -m<isa> flag: one portable binary.
libzcl_tokenguard_a_CFLAGS = -include $(srcdir)/c23/services/glue/zcl_tokenguard_symbol_prefix.h \
  -fno-strict-aliasing -fvisibility=hidden $(PIC_FLAGS) $(PIE_FLAGS) $(HARDENED_CXXFLAGS)
$(libzcl_tokenguard_a_OBJECTS): CFLAGS := $(filter-out -std=%,$(CFLAGS)) $(ZCL_C23_STD)

# crypto primitives library
crypto_libbitcoin_crypto_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_CONFIG_INCLUDES)
crypto_libbitcoin_crypto_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
crypto_libbitcoin_crypto_a_SOURCES = \
  crypto/common.h \
  crypto/equihash.cpp \
  crypto/equihash.h \
  crypto/equihash.tcc \
  crypto/hmac_sha256.cpp \
  crypto/hmac_sha256.h \
  crypto/hmac_sha512.cpp \
  crypto/hmac_sha512.h \
  crypto/ripemd160.cpp \
  crypto/ripemd160.h \
  crypto/sha1.cpp \
  crypto/sha1.h \
  crypto/sha256.cpp \
  crypto/sha256.h \
  crypto/sha3.cpp \
  crypto/sha3.h \
  crypto/sha512.cpp \
  crypto/sha512.h

if ENABLE_MINING
EQUIHASH_TROMP_SOURCES = \
  pow/tromp/equi_miner.h \
  pow/tromp/equi.h \
  pow/tromp/osx_barrier.h

crypto_libbitcoin_crypto_a_CPPFLAGS += \
  -DEQUIHASH_TROMP_ATOMIC
crypto_libbitcoin_crypto_a_SOURCES += \
  ${EQUIHASH_TROMP_SOURCES}
endif

# Vendored Z23 SHA-256 (portable C, SHA-NI, ARMv8 SHA; selected at run time) plus
# the zclassicd glue that CSHA256 calls. See c23/glue/WIRING.md, "Hash acceleration".
# No -march/-msha flag here or anywhere: the hardware transforms carry a per-function
# target attribute, so the objects stay x86-64 baseline. The include set below holds
# Z23 headers whose names collide with zclassicd (crypto/sha256.h, crypto/common.h);
# it is for these C sources ONLY and must never reach a C++ target. It is -iquote,
# not -I: Automake puts -I. (zclassicd src/) ahead of per-target flags, and -iquote
# directories are searched before every -I, so the vendored headers win here.
# zcl_c23_sha256.c #includes the vendored sha256.c, so no build output lands in
# c23/vendor/ (check-vendor.sh rejects unlisted files there).
ZCL_C23_HASH_SOURCES = \
  c23/glue/zcl_c23_sha256.c \
  c23/glue/zcl_c23_sha256.h \
  c23/glue/zcl_c23_hash_log.c \
  c23/glue/zcl_c23_hash_names.h \
  c23/glue/zcl_c23_compat.h
ZCL_C23_HASH_CPPFLAGS = \
  -iquote $(srcdir)/c23/glue \
  -iquote $(srcdir)/c23/vendor/core/modules/crypto/include \
  -iquote $(srcdir)/c23/vendor/platform/modules/util/include \
  -iquote $(srcdir)/c23/vendor/platform/modules/base/include
# -O2 first so a user CFLAGS (which Automake appends) can still override it.
ZCL_C23_HASH_CFLAGS = -O2 -std=gnu17 -include $(srcdir)/c23/glue/zcl_c23_compat.h \
  -fno-strict-aliasing -fvisibility=hidden $(SAN_CXXFLAGS) $(HARDENED_CXXFLAGS)

libzcl_c23_hash_a_SOURCES = $(ZCL_C23_HASH_SOURCES)
libzcl_c23_hash_a_CPPFLAGS = $(ZCL_C23_HASH_CPPFLAGS)
libzcl_c23_hash_a_CFLAGS = $(ZCL_C23_HASH_CFLAGS) $(PIE_FLAGS)

# common: shared between zclassicd and non-server tools
libbitcoin_common_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libbitcoin_common_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libbitcoin_common_a_SOURCES = \
  amount.cpp \
  arith_uint256.cpp \
  base58.cpp \
  bech32.cpp \
  chainparams.cpp \
  coins.cpp \
  compressor.cpp \
  consensus/params.cpp \
  consensus/upgrades.cpp \
  core_read.cpp \
  core_write.cpp \
  hash.cpp \
  key.cpp \
  key_io.cpp \
  keystore.cpp \
  netbase.cpp \
  primitives/block.cpp \
  primitives/transaction.cpp \
  protocol.cpp \
  pubkey.cpp \
  scheduler.cpp \
  script/interpreter.cpp \
  script/script.cpp \
  script/script_error.cpp \
  script/sign.cpp \
  script/standard.cpp \
  transaction_builder.cpp \
  utiltest.cpp \
  $(BITCOIN_CORE_H) \
  $(LIBZCASH_H)

# util: shared between all executables.
# This library *must* be included to make sure that the glibc
# backward-compatibility objects and their sanity checks are linked.
libbitcoin_util_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libbitcoin_util_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libbitcoin_util_a_SOURCES = \
  support/pagelocker.cpp \
  chainparamsbase.cpp \
  clientversion.cpp \
  compat/glibc_sanity.cpp \
  compat/glibcxx_sanity.cpp \
  compat/strnlen.cpp \
  random.cpp \
  rpc/protocol.cpp \
  support/cleanse.cpp \
  sync.cpp \
  uint256.cpp \
  util.cpp \
  utilmoneystr.cpp \
  utilstrencodings.cpp \
  utiltime.cpp \
  $(BITCOIN_CORE_H) \
  $(LIBZCASH_H)

if GLIBC_BACK_COMPAT
libbitcoin_util_a_SOURCES += compat/glibc_compat.cpp
endif

# cli: zclassic-cli
libbitcoin_cli_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libbitcoin_cli_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libbitcoin_cli_a_SOURCES = \
  rpc/client.cpp \
  $(BITCOIN_CORE_H) \
  $(LIBZCASH_H)

nodist_libbitcoin_util_a_SOURCES = $(srcdir)/obj/build.h
#

# bitcoind binary #
zclassicd_SOURCES = bitcoind.cpp
zclassicd_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
zclassicd_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
zclassicd_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
zclassicd_SOURCES += bitcoind-res.rc
endif

zclassicd_LDADD = \
  $(LIBBITCOIN_SERVER) \
  $(ZCL_TOR_LIBS) \
  $(LIBBITCOIN_WALLET) \
  $(LIBBITCOIN_COMMON) \
  $(LIBUNIVALUE) \
  $(LIBBITCOIN_UTIL) \
  $(LIBBITCOIN_ZMQ) \
  $(LIBBITCOIN_PROTON) \
  $(LIBBITCOIN_CRYPTO) \
  $(LIBZCASH) \
  $(LIBZCL_C23) \
  $(LIBSNARK) \
  $(LIBLEVELDB) \
  $(LIBMEMENV) \
  $(LIBSECP256K1)

zclassicd_LDADD += \
  $(BOOST_LIBS) \
  $(BDB_LIBS) \
  $(SSL_LIBS) \
  $(CRYPTO_LIBS) \
  $(EVENT_PTHREADS_LIBS) \
  $(EVENT_LIBS) \
  $(ZMQ_LIBS) \
  $(PROTON_LIBS) \
  $(LIBBITCOIN_CRYPTO) \
  $(LIBZCASH_LIBS)

# bitcoin-cli binary #
zclassic_cli_SOURCES = bitcoin-cli.cpp
zclassic_cli_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES) $(EVENT_CFLAGS)
zclassic_cli_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
zclassic_cli_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
zclassic_cli_SOURCES += bitcoin-cli-res.rc
endif

zclassic_cli_LDADD = \
  $(LIBBITCOIN_CLI) \
  $(LIBUNIVALUE) \
  $(LIBBITCOIN_UTIL) \
  $(BOOST_LIBS) \
  $(SSL_LIBS) \
  $(CRYPTO_LIBS) \
  $(EVENT_LIBS) \
  $(LIBZCASH) \
  $(LIBSNARK) \
  $(LIBBITCOIN_CRYPTO) \
  $(LIBZCASH_LIBS)
#

# zclassic-tx binary #
zclassic_tx_SOURCES = bitcoin-tx.cpp
zclassic_tx_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
zclassic_tx_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
zclassic_tx_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
zclassic_tx_SOURCES += bitcoin-tx-res.rc
endif

# FIXME: Is libzcash needed for zclassic_tx?
zclassic_tx_LDADD = \
  $(LIBUNIVALUE) \
  $(LIBBITCOIN_COMMON) \
  $(LIBBITCOIN_UTIL) \
  $(LIBSECP256K1) \
  $(LIBZCASH) \
  $(LIBZCL_C23) \
  $(LIBSNARK) \
  $(LIBBITCOIN_CRYPTO) \
  $(LIBZCASH_LIBS)

zclassic_tx_LDADD += $(BOOST_LIBS) $(CRYPTO_LIBS)
#

# zclassic protocol primitives #
libzcash_a_SOURCES = \
  zcash/tree_root.c \
  zcash/tree_root.h \
  zcash/LICENSE.tree-root \
  zcash/IncrementalMerkleTree.cpp \
  zcash/NoteEncryption.cpp \
  zcash/Address.cpp \
  zcash/JoinSplit.cpp \
  zcash/Proof.cpp \
  zcash/Note.cpp \
  zcash/prf.cpp \
  zcash/util.cpp \
  zcash/zip32.cpp \
  zcash/circuit/commitment.tcc \
  zcash/circuit/gadget.tcc \
  zcash/circuit/merkle.tcc \
  zcash/circuit/note.tcc \
  zcash/circuit/prfs.tcc \
  zcash/circuit/utils.tcc

libzcash_a_CPPFLAGS = $(AM_CPPFLAGS) $(PIC_FLAGS) -DBINARY_OUTPUT -DCURVE_ALT_BN128 -DBOOST_SPIRIT_THREADSAFE -fvisibility=hidden -DSTATIC $(BITCOIN_INCLUDES)
libzcash_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libzcash_a_CFLAGS = $(SAN_CXXFLAGS) $(HARDENED_CXXFLAGS) $(PIE_FLAGS)
libzcash_a_LDFLAGS = $(AM_LDFLAGS)

libzcash_a_CPPFLAGS += -DMONTGOMERY_OUTPUT

# C23 crypto core: vendored Z23 (verbatim), zclassicd glue, the librustzcash ABI
# shim and the Sprout Groth16 prover. Replaces librustzcash.a; nothing Rust is linked.
libzcl_c23_a_SOURCES = \
  c23/glue/zcl_c23_glue.c \
  c23/glue/zcl_c23_stubs.c \
  c23/glue/zcl_c23_tree_selftest.c \
  c23/equihash/zc23_equihash.c \
  c23/equihash/zc23_equihash_vendor.c \
  c23/compat/librustzcash_compat.c \
  c23/compat/witness_codec.c \
  c23/compat/zip32_codec.c \
  c23/sprout_prover/sprout_circuit.c \
  c23/sprout_prover/sprout_par.c \
  c23/sprout_prover/sprout_prove.c \
  c23/vendor/core/modules/crypto/src/aes256.c \
  c23/vendor/core/modules/crypto/src/blake2b.c \
  c23/vendor/core/modules/crypto/src/blake2b_avx2.c \
  c23/vendor/core/modules/crypto/src/blake2s.c \
  c23/vendor/core/modules/crypto/src/random_secret.c \
  c23/vendor/core/modules/crypto/src/sha256.c \
  c23/vendor/core/modules/crypto/src/sha512.c \
  c23/vendor/core/modules/crypto/src/simd_dispatch.c \
  c23/vendor/core/modules/sapling/src/bls12_381.c \
  c23/vendor/core/modules/sapling/src/bn254.c \
  c23/vendor/core/modules/sapling/src/bn254_accel.c \
  c23/vendor/core/modules/sapling/src/circuit_bits.c \
  c23/vendor/core/modules/sapling/src/circuit_gadgets.c \
  c23/vendor/core/modules/sapling/src/circuit_merkle.c \
  c23/vendor/core/modules/sapling/src/circuit_pedersen.c \
  c23/vendor/core/modules/sapling/src/circuit_spend.c \
  c23/vendor/core/modules/sapling/src/ff1.c \
  c23/vendor/core/modules/sapling/src/fr.c \
  c23/vendor/core/modules/sapling/src/fr_avx512.c \
  c23/vendor/core/modules/sapling/src/groth16_prover.c \
  c23/vendor/core/modules/sapling/src/jubjub.c \
  c23/vendor/core/modules/sapling/src/msm_parallel.c \
  c23/vendor/core/modules/sapling/src/params_init.c \
  c23/vendor/core/modules/sapling/src/params_vk_embedded.c \
  c23/vendor/core/modules/sapling/src/pedersen_hash.c \
  c23/vendor/core/modules/sapling/src/sapling.c \
  c23/vendor/core/modules/sapling/src/sapling_circuit.c \
  c23/vendor/core/modules/sapling/src/sapling_prover_c23.c \
  c23/vendor/core/modules/sapling/src/sapling_prover_native.c \
  c23/vendor/core/modules/sapling/src/sprout.c \
  c23/vendor/core/modules/sapling/src/zip32.c \
  c23/vendor/platform/modules/base/src/safe_alloc.c \
  c23/vendor/platform/modules/encoding/src/utilstrencodings.c \
  c23/vendor/platform/modules/platform/src/file_stream.c \
  c23/vendor/platform/modules/util/src/file_io.c

# This -I set is for the C library ONLY. Z23 header names (chainparams.h,
# crypto/sha256.h, core/uint256.h, ...) collide with zclassicd's, so none of
# these directories may ever reach a C++ target; C++ sees only c23/compat.
# c23/glue comes first (its chain/chainparams.h and zcl_c23_compat.h must win).
libzcl_c23_a_CPPFLAGS = $(HARDENED_CPPFLAGS) $(ZCL_C23_STD_DEFS) \
  -I$(srcdir)/c23/glue -I$(srcdir)/c23/glue/chain \
  -I$(srcdir)/c23/compat -I$(srcdir)/c23/sprout_prover \
  -I$(srcdir)/c23/vendor/core/modules/sapling/include \
  -I$(srcdir)/c23/vendor/core/modules/sapling/src \
  -I$(srcdir)/c23/vendor/core/modules/crypto/include \
  -I$(srcdir)/c23/vendor/core/modules/core/include \
  -I$(srcdir)/c23/vendor/core/math/include \
  -I$(srcdir)/c23/vendor/platform/modules/base/include \
  -I$(srcdir)/c23/vendor/platform/modules/util/include \
  -I$(srcdir)/c23/vendor/platform/modules/support/include \
  -I$(srcdir)/c23/vendor/platform/modules/platform/include \
  -I$(srcdir)/c23/vendor/platform/modules/encoding/include

if TARGET_WINDOWS
# mingw-w64 older than v8 (Ubuntu 20.04, the release container):
# - defaults _WIN32_WINNT to 0x0502, which hides WC_ERR_INVALID_CHARS (the shim's
#   parameter path conversion) and GetTickCount64 (Sprout prover timer); both
#   exist from Windows Vista on, and Windows 7 is the floor for these objects;
# - does not turn on its C99 printf for C code under _GNU_SOURCE, so "%zu" would
#   go to msvcrt's printf, which does not know it and then misreads the
#   arguments that follow.
libzcl_c23_a_CPPFLAGS += -D_WIN32_WINNT=0x0601 -D__USE_MINGW_ANSI_STDIO=1
endif

# No -march / -m<isa> flag: one portable binary, ADX/BMI2/AVX2/AVX-512 paths are
# function-target-attribute code selected at run time (simd_dispatch.c).
# -fomit-frame-pointer is required by the ADX inline asm (it needs a spare GPR).
# Never define ZCL_TESTING, ZCL_C23_COMPAT_TESTING or ZCL_FUZZ_QUIET_LOG_MACROS here.
# $(ZCL_C23_LTO_CFLAGS) is empty by default: see doc/c23-build.md.
libzcl_c23_a_CFLAGS = -include $(srcdir)/c23/glue/zcl_c23_symbol_prefix.h \
  -include $(srcdir)/c23/glue/zcl_c23_compat.h \
  -fomit-frame-pointer -fno-strict-aliasing -fvisibility=hidden \
  $(PTHREAD_CFLAGS) $(PIC_FLAGS) $(PIE_FLAGS) $(SAN_CXXFLAGS) $(HARDENED_CXXFLAGS) \
  $(ZCL_C23_LTO_CFLAGS)

# Automake puts $(CFLAGS) after the per-target flags, so a depends/user
# "-std=gnu17 -O2" would win. For these objects only, drop any -std= and -O from
# CFLAGS and end with the configure-selected language level and -O3.
$(libzcl_c23_a_OBJECTS): CFLAGS := $(filter-out -std=% -O%,$(CFLAGS)) $(ZCL_C23_STD) -O3
# Automake's DEFAULT_INCLUDES (-I. first) would let Z23's "crypto/sha512.h", "chainparams.h"
# ... resolve to zclassicd's C++ headers of the same name. Not for these objects.
$(libzcl_c23_a_OBJECTS): DEFAULT_INCLUDES :=

# C++ side of the glue seams (LogPrintStr, -debug=zc23, network id).
libzcl_c23_seam_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libzcl_c23_seam_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libzcl_c23_seam_a_SOURCES = \
  c23/glue/zcl_c23_glue.h \
  c23/glue/zcl_c23_log.cpp

# Z23 exports generic C names (blake2b_init, sha256_init, fr_add, ...) and
# libsodium.a exports some of the same ones (its reference BLAKE2b). The
# force-included c23/glue/zcl_c23_symbol_prefix.h renames every internal global
# of the core to zc23_<name>; this stamp proves the archive exports nothing
# else, and every program that links the core waits for it.
c23-symbols.stamp: libzcl_c23.a libzcl_c23_hash.a libzcl_tokenguard.a libzcl_tor.a $(srcdir)/c23/tools/symbol-prefix.sh
	$(AM_V_GEN) sh $(srcdir)/c23/tools/symbol-prefix.sh check "$(NM)" libzcl_c23.a && \
	  sh $(srcdir)/c23/tools/symbol-prefix.sh check "$(NM)" libzcl_c23_hash.a && \
	  sh $(srcdir)/c23/tools/symbol-prefix.sh check "$(NM)" libzcl_tokenguard.a && \
	  sh $(srcdir)/c23/tools/symbol-prefix.sh check "$(NM)" libzcl_tor.a && touch $@
EXTRA_zclassicd_DEPENDENCIES = c23-symbols.stamp
EXTRA_zclassic_tx_DEPENDENCIES = c23-symbols.stamp
EXTRA_zclassic_cli_DEPENDENCIES = c23-symbols.stamp

# Source-identity gate for the vendored subtree (not part of "make all").
check-c23-vendor:
	sh $(srcdir)/c23/tools/check-vendor.sh
	sh $(srcdir)/c23/services/tools/check-vendor.sh $(srcdir)/c23/services

# The linker must never see a Rust archive. Run after a build.
check-c23-no-rust: $(bin_PROGRAMS)
	sh $(srcdir)/c23/tools/check-no-rust.sh "$(NM)" $(bin_PROGRAMS)

# zcashconsensus library #
if BUILD_BITCOIN_LIBS
include_HEADERS = script/zcashconsensus.h
libzcashconsensus_la_SOURCES = \
  crypto/equihash.cpp \
  crypto/hmac_sha512.cpp \
  crypto/ripemd160.cpp \
  crypto/sha1.cpp \
  crypto/sha256.cpp \
  crypto/sha512.cpp \
  hash.cpp \
  primitives/transaction.cpp \
  pubkey.cpp \
  script/zcashconsensus.cpp \
  script/interpreter.cpp \
  script/script.cpp \
  script/sigencoding.cpp \
  uint256.cpp \
  utilstrencodings.cpp

if GLIBC_BACK_COMPAT
  libzcashconsensus_la_SOURCES += compat/glibc_compat.cpp
endif

libzcashconsensus_la_LDFLAGS = $(AM_LDFLAGS) -no-undefined $(RELDFLAGS)
# libzcashconsensus compiles crypto/sha256.cpp itself, so it needs the C backend too.
noinst_LTLIBRARIES = libzcl_c23_hash_pic.la
libzcl_c23_hash_pic_la_SOURCES = $(ZCL_C23_HASH_SOURCES)
libzcl_c23_hash_pic_la_CPPFLAGS = $(ZCL_C23_HASH_CPPFLAGS)
libzcl_c23_hash_pic_la_CFLAGS = $(ZCL_C23_HASH_CFLAGS)
libzcashconsensus_la_LIBADD = $(LIBSECP256K1) libzcl_c23_hash_pic.la
libzcashconsensus_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(builddir)/obj -I$(srcdir)/secp256k1/include -DBUILD_BITCOIN_INTERNAL
libzcashconsensus_la_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)

endif
#

CLEANFILES = c23-symbols.stamp leveldb/libleveldb.a leveldb/libmemenv.a *.gcda *.gcno */*.gcno wallet/*/*.gcno

DISTCLEANFILES = obj/build.h

EXTRA_DIST = leveldb snark test/tree_root_c_tests.c \
  c23/services/README.md \
  c23/services/NOTICE \
  c23/services/LICENSE.z23 \
  c23/services/Z23_SOURCE.tsv \
  c23/services/vendor/.gitattributes \
  c23/services/tools/check-vendor.sh \
  c23/services/tools/revendor.sh \
  c23/services/tools/vendor-files.txt \
  c23/services/tools/z23-vector-check.sh \
  c23/services/tools/z23_vector_shim.h \
  c23/services/tools/slpscript.c

clean-local:
	-$(MAKE) -C leveldb clean
	-$(MAKE) -C secp256k1 clean
	-$(MAKE) -C snark clean
	-$(MAKE) -C univalue clean
	rm -f leveldb/*/*.gcno leveldb/helpers/memenv/*.gcno
	-rm -f config.h

.rc.o:
	@test -f $(WINDRES)
	$(AM_V_GEN) $(WINDRES) -DWINDRES_PREPROC -i $< -o $@

.mm.o:
	$(AM_V_CXX) $(OBJCXX) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) \
	  $(CPPFLAGS) $(AM_CXXFLAGS) $(AM_CXXFLAGS) $(PIE_FLAGS) $(CXXFLAGS) -c -o $@ $<

check-symbols: $(bin_PROGRAMS)
if GLIBC_BACK_COMPAT
	@echo "Checking glibc back compat of [$(bin_PROGRAMS)]..."
	$(AM_V_at) READELF=$(READELF) CPPFILT=$(CPPFILT) $(top_srcdir)/contrib/devtools/symbol-check.py $(bin_PROGRAMS)
endif

check-security: $(bin_PROGRAMS)
if HARDEN
	@echo "Checking binary security of [$(bin_PROGRAMS)]..."
	$(AM_V_at) READELF=$(READELF) OBJDUMP=$(OBJDUMP) $(top_srcdir)/contrib/devtools/security-check.py $(bin_PROGRAMS)
endif

strip: $(bin_PROGRAMS)
	@echo "Stripping binaries to reduce size..."
	$(AM_V_at)$(STRIP) $(bin_PROGRAMS)

%.pb.cc %.pb.h: %.proto
	@test -f $(PROTOC)
	$(AM_V_GEN) $(PROTOC) --cpp_out=$(@D) --proto_path=$(abspath $(<D) $<)

if ENABLE_TESTS
include Makefile.test.include
include Makefile.gtest.include
endif
