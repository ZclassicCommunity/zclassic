# zcl-dev-wiki: one binary that is also zcl-dev-read, zcl-dev-lessons and zcl-dev-know (it acts
# by the name it is run under, so zcl-dev's git-style dispatch finds each). Libc only; builds with
# the host cc, the mingw cross compiler and macOS clang. Outputs go to ../../bin (git-ignored).
#   make -C zcutil/dev/wiki                                        host compiler
#   make -C zcutil/dev/wiki CC=x86_64-w64-mingw32-gcc EXEEXT=.exe  cross build
#   make -C zcutil/dev/wiki check                                  build and run the fixture tests
CC ?= cc
EXEEXT ?=
CFLAGS ?= -O2 -g
STD ?= -std=gnu17
WARN ?= -Wall -Wextra -Werror
BIN = ../../bin
SRC = wiki.c facts.c wikilib.c
HDR = wikilib.h
ALIASES = read lessons know
ALIAS_BINS = $(ALIASES:%=$(BIN)/zcl-dev-%$(EXEEXT))
ifneq ($(EXEEXT),)
CFLAGS += -D__USE_MINGW_ANSI_STDIO=1
endif

all: $(BIN)/zcl-dev-wiki$(EXEEXT) $(ALIAS_BINS)

$(BIN)/zcl-dev-wiki$(EXEEXT): $(SRC) $(HDR)
	mkdir -p $(BIN)
	$(CC) $(STD) $(WARN) $(CFLAGS) -o $@ $(SRC)

# A copy, not a link: Windows has no portable symlinks.
$(ALIAS_BINS): $(BIN)/zcl-dev-wiki$(EXEEXT)
	cp $< $@

# The fixture tests check JSON replies with jsonq.
$(BIN)/jsonq$(EXEEXT):
	$(MAKE) -C ../../tools EXEEXT=$(EXEEXT) CC=$(CC)

check: all $(BIN)/jsonq$(EXEEXT)
	sh test/run.sh $(BIN)
	$(MAKE) -s c2x
	$(BIN)/zcl-dev-know$(EXEEXT) -C ../../.. --check

# Every file also compiles as C23 (a syntax check only).
c2x: $(SRC) $(HDR)
	for f in $(SRC); do $(CC) -std=c2x $(WARN) -fsyntax-only $$f || exit 1; done

clean:
	rm -f $(BIN)/zcl-dev-wiki $(BIN)/zcl-dev-wiki.exe
	for a in $(ALIASES); do rm -f $(BIN)/zcl-dev-$$a $(BIN)/zcl-dev-$$a.exe; done

.PHONY: all check c2x clean
