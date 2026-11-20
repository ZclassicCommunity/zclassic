# fixture autotools file: += , $(VAR) expansion, conditionals, continuation lines
CORE_H = \
  a.h \
  b.h \
  common.h

LIBFX_CORE=libfx_core.a
LIBFX_WALLET=libfx_wallet.a
if ENABLE_WALLET
LIBFX_EXTRA=libfx_wallet.a
else
LIBFX_EXTRA=libfx_none.a
endif

EXTRA_LIBRARIES = $(LIBFX_CORE) $(LIBFX_WALLET)
bin_PROGRAMS =
noinst_PROGRAMS =
if BUILD_FXD
  bin_PROGRAMS += fxd
endif

libfx_core_a_SOURCES = \
  core.cpp \
  $(CORE_H)
libfx_core_a_SOURCES += extra.cpp

libfx_wallet_a_SOURCES = wallet/wallet.cpp wallet/wallet.h

fxd_SOURCES = main.cpp
fxd_LDADD = $(LIBFX_CORE) $(LIBFX_EXTRA) $(BOOST_LIBS)

include Makefile.test.include
