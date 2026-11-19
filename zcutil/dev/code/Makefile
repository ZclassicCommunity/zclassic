# zcl-dev-code: code intelligence for the zclassicd tree (map, owner, impact, cost, file, sym, refs,
# body, recent). Libc only; builds with the host cc, the mingw cross compiler and macOS clang.
# Output goes to ../../bin (git-ignored).
#   make -C zcutil/dev/code                                        host compiler
#   make -C zcutil/dev/code CC=x86_64-w64-mingw32-gcc EXEEXT=.exe  cross build
#   make -C zcutil/dev/code check                                  build, C2x compile check, fixture tests
CC ?= cc
EXEEXT ?=
CFLAGS ?= -O2 -g
STD ?= -std=gnu17
WARN ?= -Wall -Wextra -Werror
INC = -I../../tools/vendor
BIN = ../../bin
LIBSRC = ../lib/cxxscan.c ../lib/gitfiles.c ../lib/incgraph.c ../lib/automake.c
LIBHDR = ../lib/cxxscan.h ../lib/gitfiles.h ../lib/incgraph.h ../lib/automake.h
HDR = ../../tools/vendor/platform/modules/platform/include/platform/glob_match.h
ifneq ($(EXEEXT),)
CFLAGS += -D__USE_MINGW_ANSI_STDIO=1
endif

all: $(BIN)/zcl-dev-code$(EXEEXT)

$(BIN)/zcl-dev-code$(EXEEXT): code.c $(LIBSRC) $(LIBHDR) $(HDR)
	mkdir -p $(BIN)
	$(CC) $(STD) $(WARN) $(CFLAGS) $(INC) -o $@ code.c $(LIBSRC)

# Every file must also compile as C2x (the language of Z23); no object is kept.
c2x:
	for f in code.c $(LIBSRC); do $(CC) -std=c2x $(WARN) $(CFLAGS) $(INC) -c -o /dev/null $$f || exit 1; done

check: $(BIN)/zcl-dev-code$(EXEEXT) c2x
	sh test/run.sh $(BIN)/zcl-dev-code$(EXEEXT)

clean:
	rm -f $(BIN)/zcl-dev-code $(BIN)/zcl-dev-code.exe

.PHONY: all check clean c2x
