# zcl-dev-compdb: compile_commands.json for clangd from a configured build. Libc only; builds with
# the host cc, the mingw cross compiler and macOS clang. Output goes to ../../bin (git-ignored).
#   make -C zcutil/dev/compdb                                        host compiler
#   make -C zcutil/dev/compdb CC=x86_64-w64-mingw32-gcc EXEEXT=.exe  cross build
#   make -C zcutil/dev/compdb check                                  build, compile as C23, selftest, fixture tests
CC ?= cc
EXEEXT ?=
CFLAGS ?= -O2 -g
STD ?= -std=gnu17
WARN ?= -Wall -Wextra -Werror
BIN = ../../bin
ifneq ($(EXEEXT),)
CFLAGS += -D__USE_MINGW_ANSI_STDIO=1
endif

all: $(BIN)/zcl-dev-compdb$(EXEEXT)

$(BIN)/zcl-dev-compdb$(EXEEXT): zcl-dev-compdb.c
	mkdir -p $(BIN)
	$(CC) $(STD) $(WARN) $(CFLAGS) -o $@ zcl-dev-compdb.c

check: $(BIN)/zcl-dev-compdb$(EXEEXT)
	$(CC) -std=c2x $(WARN) -fsyntax-only zcl-dev-compdb.c
	$(BIN)/zcl-dev-compdb$(EXEEXT) --selftest
	sh test/run.sh $(BIN)/zcl-dev-compdb$(EXEEXT)

clean:
	rm -f $(BIN)/zcl-dev-compdb $(BIN)/zcl-dev-compdb.exe

.PHONY: all check clean
