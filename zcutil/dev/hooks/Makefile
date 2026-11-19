# zcl-dev-hooks (`zcl-dev hooks install|status`) and zcl-dev-hook (what the git hook shims exec):
# one source, one binary, two names. Libc only; host cc, mingw cross compiler and macOS clang.
# Outputs go to ../../bin (git-ignored).
#   make -C zcutil/dev/hooks                                        host compiler
#   make -C zcutil/dev/hooks CC=x86_64-w64-mingw32-gcc EXEEXT=.exe  cross build
#   make -C zcutil/dev/hooks check                                  fixture-repo tests
CC ?= cc
EXEEXT ?=
CFLAGS ?= -O2 -g
STD ?= -std=gnu17
WARN ?= -Wall -Wextra -Werror
BIN = ../../bin
ifneq ($(EXEEXT),)
CFLAGS += -D__USE_MINGW_ANSI_STDIO=1
endif

all: $(BIN)/zcl-dev-hooks$(EXEEXT) $(BIN)/zcl-dev-hook$(EXEEXT)

$(BIN)/zcl-dev-hooks$(EXEEXT): zcl-dev-hooks.c
	mkdir -p $(BIN)
	$(CC) $(STD) $(WARN) $(CFLAGS) -o $@ zcl-dev-hooks.c

$(BIN)/zcl-dev-hook$(EXEEXT): $(BIN)/zcl-dev-hooks$(EXEEXT)
	cp $< $@

# The pre-push test drives the real zcl-dev select, so build the dev tools first.
check: all
	$(MAKE) -C .. all EXEEXT=$(EXEEXT)
	sh test/run.sh $(BIN)

clean:
	rm -f $(BIN)/zcl-dev-hook $(BIN)/zcl-dev-hook.exe $(BIN)/zcl-dev-hooks $(BIN)/zcl-dev-hooks.exe

.PHONY: all check clean
