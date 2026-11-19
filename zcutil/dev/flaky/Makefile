# zcl-dev-flaky (`zcl-dev flaky`): repeat a command N times in isolated directories. Libc only;
# POSIX implementation, the mingw build prints UNAVAILABLE. Outputs go to ../../bin (git-ignored).
#   make -C zcutil/dev/flaky                                        host compiler
#   make -C zcutil/dev/flaky CC=x86_64-w64-mingw32-gcc EXEEXT=.exe  cross build
#   make -C zcutil/dev/flaky check                                  --selftest and fixture-command tests (test/flaky_test.c)
CC ?= cc
EXEEXT ?=
CFLAGS ?= -O2 -g
STD ?= -std=gnu17
WARN ?= -Wall -Wextra -Werror
BIN = ../../bin
ifneq ($(EXEEXT),)
CFLAGS += -D__USE_MINGW_ANSI_STDIO=1
endif
TOOL = $(BIN)/zcl-dev-flaky$(EXEEXT)

all: $(TOOL)

$(TOOL): zcl-dev-flaky.c
	mkdir -p $(BIN)
	$(CC) $(STD) $(WARN) $(CFLAGS) -o $@ zcl-dev-flaky.c

check: $(TOOL)
	$(CC) -std=c2x $(WARN) -fsyntax-only zcl-dev-flaky.c
	$(TOOL) --selftest
ifeq ($(EXEEXT),)
	$(CC) $(STD) $(WARN) $(CFLAGS) -o $(BIN)/zcl-dev-flaky-test test/flaky_test.c
	$(BIN)/zcl-dev-flaky-test $(TOOL)
endif

clean:
	rm -f $(BIN)/zcl-dev-flaky $(BIN)/zcl-dev-flaky.exe $(BIN)/zcl-dev-flaky-test

.PHONY: all check clean
