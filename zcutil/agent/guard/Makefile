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

RULES = rules.c rules_text.c rules_esc.c rules_net.c rules_push.c rules_home.c rules_rpc.c \
  rules_glob.c rules_path.c rules_ident.c
HDRS = rules.h rules_int.h

# The vendored Z23 files compile warning-free under the same -Werror flags.
$(BIN)/zcl-agent-guard$(EXEEXT): zcl-agent-guard.c $(RULES) $(HDRS) $(VSRC)
	mkdir -p $(BIN)
	$(CC) $(STD) $(WARN) $(CFLAGS) $(VINC) -I. -o $@ zcl-agent-guard.c $(RULES) \
	  $(VSRC)

$(TEST_BIN): test/selftest.c test/rows2.c test/cases.h $(RULES) $(HDRS)
	mkdir -p $(BIN)
	$(CC) $(STD) $(WARN) $(CFLAGS) -I. -o $@ test/selftest.c test/rows2.c $(RULES)

# Every file must also compile as c2x (the Z23 baseline), with no warnings.
c2x-compile:
	@set -e; for f in zcl-agent-guard.c $(RULES) test/selftest.c test/rows2.c; do \
	  $(CC) -std=c2x $(WARN) -D__USE_MINGW_ANSI_STDIO=1 $(VINC) -I. -fsyntax-only $$f; \
	done; echo "c2x-compile: OK ($(CC))"

ROOT = ../../..
LIST = $(BIN)/zcl-agent-guard-scripts.lst
FX = $(BIN)/zcl-agent-guard-fixtures

# The rule table, then the no-false-refusal suites: test/ordinary.txt (ordinary commands, all
# allowed) and every tracked script of the repository written back through the Write path.
check: $(BIN)/zcl-agent-guard$(EXEEXT) $(TEST_BIN) c2x-compile
	git -C $(ROOT) ls-files -- '*.sh' '*.ps1' '*.cmd' '*.bat' > $(LIST) 2>/dev/null || : > $(LIST)
	rm -rf $(FX) && mkdir -p $(FX)/m/.git $(FX)/m/sub/deep $(FX)/f/.git $(FX)/f/sub/deep $(FX)/w $(FX)/wgit
	echo 'ref: refs/heads/master' > $(FX)/m/.git/HEAD
	echo 'ref: refs/heads/factory/x' > $(FX)/f/.git/HEAD
	echo 'gitdir: ../wgit' > $(FX)/w/.git
	echo 'ref: refs/heads/master' > $(FX)/wgit/HEAD
	$(TEST_BIN) --ordinary test/ordinary.txt --scripts $(LIST) --root $(ROOT) --fixtures $(abspath $(FX))
	sh test/run.sh $(BIN)/zcl-agent-guard$(EXEEXT)

clean:
	rm -rf $(BIN)/zcl-agent-guard $(BIN)/zcl-agent-guard.exe $(TEST_BIN) $(LIST) $(FX)

.PHONY: all check clean c2x-compile
