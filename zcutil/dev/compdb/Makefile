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

TEST = $(BIN)/zcl-compdb-test$(EXEEXT)

$(TEST): test/compdb_test.c zcl-dev-compdb.c
	mkdir -p $(BIN)
	$(CC) $(STD) $(WARN) $(CFLAGS) -o $@ test/compdb_test.c

check: $(BIN)/zcl-dev-compdb$(EXEEXT) $(TEST)
	$(CC) -std=c2x $(WARN) -fsyntax-only zcl-dev-compdb.c test/compdb_test.c
	$(BIN)/zcl-dev-compdb$(EXEEXT) --selftest
	$(TEST) test/fixtures

clean:
	rm -f $(BIN)/zcl-dev-compdb $(BIN)/zcl-dev-compdb.exe $(BIN)/zcl-compdb-test $(BIN)/zcl-compdb-test.exe

.PHONY: all check clean
