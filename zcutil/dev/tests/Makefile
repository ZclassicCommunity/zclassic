# zcl-dev-tests: focused C++ test selection (tests, t-fast, t-list, check-tests). One source, one
# binary, installed under one name per command (zcl-dev dispatches to zcutil/bin/zcl-dev-<cmd>).
# Libc only; host cc, mingw cross compiler and macOS clang. Outputs go to ../../bin (git-ignored).
#   make -C zcutil/dev/tests                                        host compiler
#   make -C zcutil/dev/tests CC=x86_64-w64-mingw32-gcc EXEEXT=.exe  cross build
#   make -C zcutil/dev/tests check                                  fixture self-test
CC ?= cc
EXEEXT ?=
CFLAGS ?= -O2 -g
STD ?= -std=gnu17
WARN ?= -Wall -Wextra -Werror
INC = -I../../tools/vendor
HDR = ../../tools/vendor/platform/modules/platform/include/platform/glob_match.h
BIN = ../../bin
CMDS = tests t-fast t-list check-tests
OUTS = $(CMDS:%=$(BIN)/zcl-dev-%$(EXEEXT))
ifneq ($(EXEEXT),)
CFLAGS += -D__USE_MINGW_ANSI_STDIO=1
endif

all: $(OUTS)

$(BIN)/zcl-dev-tests$(EXEEXT): zcl-dev-tests.c $(HDR)
	mkdir -p $(BIN)
	$(CC) $(STD) $(WARN) $(CFLAGS) $(INC) -o $@ zcl-dev-tests.c

# The other names are copies of the first: the command is the binary's own file name.
$(BIN)/zcl-dev-%$(EXEEXT): $(BIN)/zcl-dev-tests$(EXEEXT)
	cp $< $@

check: $(OUTS)
	$(CC) -std=c2x $(WARN) -fsyntax-only $(INC) zcl-dev-tests.c
	sh test/run.sh $(BIN)

clean:
	rm -f $(OUTS)

.PHONY: all check clean
