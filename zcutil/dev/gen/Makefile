# zcl-dev-gen: generated RPC/argument references, capability inventory and parity gates. Libc only;
# builds with the host cc, the mingw cross compiler and macOS clang. Output goes to ../../bin.
#   make -C zcutil/dev/gen                                        host compiler
#   make -C zcutil/dev/gen CC=x86_64-w64-mingw32-gcc EXEEXT=.exe  cross build
#   make -C zcutil/dev/gen check                                  build, compile as C23, run the fixture tests
CC ?= cc
EXEEXT ?=
CFLAGS ?= -O2 -g
STD ?= -std=gnu17
WARN ?= -Wall -Wextra -Werror
BIN = ../../bin
ifneq ($(EXEEXT),)
CFLAGS += -D__USE_MINGW_ANSI_STDIO=1
endif

all: $(BIN)/zcl-dev-gen$(EXEEXT)

$(BIN)/zcl-dev-gen$(EXEEXT): gen.c
	mkdir -p $(BIN)
	$(CC) $(STD) $(WARN) $(CFLAGS) -o $@ gen.c

check: $(BIN)/zcl-dev-gen$(EXEEXT)
	$(CC) -std=c2x $(WARN) -fsyntax-only gen.c
	$(BIN)/zcl-dev-gen$(EXEEXT) --selftest
	sh test/run.sh $(BIN)/zcl-dev-gen$(EXEEXT)

clean:
	rm -f $(BIN)/zcl-dev-gen $(BIN)/zcl-dev-gen.exe

.PHONY: all check clean
