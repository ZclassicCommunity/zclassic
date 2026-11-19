# zcl-dev-timings (`zcl-dev timings`): step durations over local-ci result directories. Libc only;
# host cc, mingw cross compiler and macOS clang. Outputs go to ../../bin (git-ignored).
#   make -C zcutil/dev/timings                                        host compiler
#   make -C zcutil/dev/timings CC=x86_64-w64-mingw32-gcc EXEEXT=.exe  cross build
#   make -C zcutil/dev/timings check                                  --selftest and golden outputs over fixtures
CC ?= cc
EXEEXT ?=
CFLAGS ?= -O2 -g
STD ?= -std=gnu17
WARN ?= -Wall -Wextra -Werror
BIN = ../../bin
ifneq ($(EXEEXT),)
CFLAGS += -D__USE_MINGW_ANSI_STDIO=1
endif
TOOL = $(BIN)/zcl-dev-timings$(EXEEXT)

all: $(TOOL)

$(TOOL): zcl-dev-timings.c
	mkdir -p $(BIN)
	$(CC) $(STD) $(WARN) $(CFLAGS) -o $@ zcl-dev-timings.c

check: $(TOOL)
	$(CC) -std=c2x $(WARN) -fsyntax-only zcl-dev-timings.c
	$(TOOL) --selftest
ifeq ($(EXEEXT),)
	sh test/run.sh $(TOOL)
endif

clean:
	rm -f $(BIN)/zcl-dev-timings $(BIN)/zcl-dev-timings.exe

.PHONY: all check clean
