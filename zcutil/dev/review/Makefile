# zcl-dev-review (`zcl-dev review record|check`): the review record doc/agent/REVIEWS.tsv. One source plus
# review-core.c, which zcutil/dev/hooks compiles in as well. Libc only; host cc, mingw cross compiler and
# macOS clang. Outputs go to ../../bin (git-ignored).
#   make -C zcutil/dev/review                                        host compiler
#   make -C zcutil/dev/review CC=x86_64-w64-mingw32-gcc EXEEXT=.exe  cross build
#   make -C zcutil/dev/review check                                  selftest and fixture-repo tests
CC ?= cc
EXEEXT ?=
CFLAGS ?= -O2 -g
STD ?= -std=gnu17
WARN ?= -Wall -Wextra -Werror
BIN = ../../bin
SRCS = zcl-dev-review.c review-core.c
HDRS = review-core.h
ifneq ($(EXEEXT),)
CFLAGS += -D__USE_MINGW_ANSI_STDIO=1
endif

all: $(BIN)/zcl-dev-review$(EXEEXT)

$(BIN)/zcl-dev-review$(EXEEXT): $(SRCS) $(HDRS)
	mkdir -p $(BIN)
	$(CC) $(STD) $(WARN) $(CFLAGS) -o $@ $(SRCS)

check: all
	$(CC) -std=c2x $(WARN) -fsyntax-only zcl-dev-review.c
	$(CC) -std=c2x $(WARN) -fsyntax-only review-core.c
	$(BIN)/zcl-dev-review$(EXEEXT) --selftest
	sh test/run.sh $(BIN)/zcl-dev-review$(EXEEXT)

clean:
	rm -f $(BIN)/zcl-dev-review $(BIN)/zcl-dev-review.exe

.PHONY: all check clean
