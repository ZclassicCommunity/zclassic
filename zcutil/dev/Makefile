# zcl-dev: developer tool. Libc only; builds with the host cc, the mingw cross compiler
# (make mingw) and macOS clang.  `make check` builds it and runs the fixture tests.
CC ?= cc
CFLAGS ?= -O2 -g
STD ?= -std=gnu17
WARN ?= -Wall -Wextra -Werror
INC = -I../tools/vendor
HDR = ../tools/vendor/platform/modules/platform/include/platform/glob_match.h
MINGW ?= x86_64-w64-mingw32-gcc

all: zcl-dev

zcl-dev: zcl-dev.c $(HDR)
	$(CC) $(STD) $(WARN) $(CFLAGS) $(INC) -o $@ zcl-dev.c

mingw: zcl-dev.exe

zcl-dev.exe: zcl-dev.c $(HDR)
	$(MINGW) $(STD) $(WARN) $(CFLAGS) $(INC) -o $@ zcl-dev.c

check: zcl-dev
	sh test/run.sh ./zcl-dev
	sh test/ci-receipts.sh ./zcl-dev
	sh zcl-port-selftest.sh
	./zcl-dev check-rules
	./zcl-dev check-docs

clean:
	rm -f zcl-dev zcl-dev.exe

.PHONY: all mingw check clean
