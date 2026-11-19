# zcl-agent-guard: the Claude Code PreToolUse hook. Libc only; builds with the host cc, the mingw
# cross compiler and macOS clang. Output goes to ../../bin (git-ignored).
#   make -C zcutil/agent/guard                                         host compiler
#   make -C zcutil/agent/guard CC=x86_64-w64-mingw32-gcc EXEEXT=.exe   cross build
#   make -C zcutil/agent/guard check                                   self-test, hook and replay tests
CC ?= cc
EXEEXT ?=
CFLAGS ?= -O2 -g
STD ?= -std=gnu17
WARN ?= -Wall -Wextra -Werror
BIN = ../../bin
V = ../../tools/vendor
VINC = -I$(V)/contexts/commons/packages/zjsonp/include -I$(V)/contexts/commons/packages/zutf8/include
VSRC = $(V)/contexts/commons/packages/zjsonp/src/zjsonp.c $(V)/contexts/commons/packages/zutf8/src/zutf8.c
ifneq ($(EXEEXT),)
CFLAGS += -D__USE_MINGW_ANSI_STDIO=1
endif
TEST_BIN = $(BIN)/zcl-agent-guard-selftest$(EXEEXT)

all: $(BIN)/zcl-agent-guard$(EXEEXT)

# The vendored Z23 files compile warning-free under the same -Werror flags.
$(BIN)/zcl-agent-guard$(EXEEXT): zcl-agent-guard.c rules.c rules.h $(VSRC)
	mkdir -p $(BIN)
	$(CC) $(STD) $(WARN) $(CFLAGS) $(VINC) -I. -o $@ zcl-agent-guard.c rules.c \
	  $(VSRC)

$(TEST_BIN): test/selftest.c rules.c rules.h
	mkdir -p $(BIN)
	$(CC) $(STD) $(WARN) $(CFLAGS) -I. -o $@ test/selftest.c rules.c

# Every file must also compile as c2x (the Z23 baseline), with no warnings.
c2x-compile:
	@set -e; for f in zcl-agent-guard.c rules.c test/selftest.c; do \
	  $(CC) -std=c2x $(WARN) -D__USE_MINGW_ANSI_STDIO=1 $(VINC) -I. -fsyntax-only $$f; \
	done; echo "c2x-compile: OK ($(CC))"

check: $(BIN)/zcl-agent-guard$(EXEEXT) $(TEST_BIN) c2x-compile
	$(TEST_BIN)
	sh test/run.sh $(BIN)/zcl-agent-guard$(EXEEXT)

clean:
	rm -f $(BIN)/zcl-agent-guard $(BIN)/zcl-agent-guard.exe $(TEST_BIN)

.PHONY: all check clean c2x-compile
