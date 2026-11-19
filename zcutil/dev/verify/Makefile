# zcl-dev-verify: one-trip verify of committed changes. Libc only; host cc, clang or the mingw cross compiler.
#   make -C zcutil/dev/verify [CC=x86_64-w64-mingw32-gcc EXEEXT=.exe]    build into ../../bin
#   make -C zcutil/dev/verify check                                      --selftest and the fixture test
CC ?= cc
EXEEXT ?=
CFLAGS ?= -O2 -g
STD ?= -std=gnu17
WARN ?= -Wall -Wextra -Werror
BIN = ../../bin
ifneq ($(EXEEXT),)
CFLAGS += -D__USE_MINGW_ANSI_STDIO=1
endif
TOOL = $(BIN)/zcl-dev-verify$(EXEEXT)

all: $(TOOL)

$(TOOL): zcl-verify.c
	mkdir -p $(BIN)
	$(CC) $(STD) $(WARN) $(CFLAGS) -o $@ zcl-verify.c

# the tool must also compile as C2x (the language of Z23); no object is kept
c2x:
	$(CC) -std=c2x $(WARN) $(CFLAGS) -c -o /dev/null zcl-verify.c

check: $(TOOL) c2x
	$(TOOL) --selftest
	sh test/run.sh $(TOOL)

clean:
	rm -f $(BIN)/zcl-dev-verify $(BIN)/zcl-dev-verify.exe

.PHONY: all check clean c2x
