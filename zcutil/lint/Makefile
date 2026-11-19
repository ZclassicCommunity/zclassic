# zcl-lint: ratchet gates (jq, bash, banned string functions, markdown links, vendored files).
#   make -C zcutil/lint              build ../bin/zcl-lint
#   make -C zcutil/lint check        selftest of every rule against fixture repositories
#   make -C zcutil/lint lint         run all rules on this tree (also: make -C src lint-fast)
# Rules: see rules.def; selftest.sh and selftest_shape.sh drive fixture repositories.
# Sources: zcl-lint.c (driver), lintlib.{c,h} (shared helpers), rules/*.c (one file per rule), rules.def.
CC ?= cc
EXEEXT ?=
CFLAGS ?= -O2
ifneq ($(EXEEXT),)
CFLAGS += -D__USE_MINGW_ANSI_STDIO=1
endif
OUT = ../bin/zcl-lint$(EXEEXT)
RULES = $(wildcard rules/*.c)
SRC = zcl-lint.c lintlib.c $(RULES)
HDR = lintlib.h rules.def

all: $(OUT)

$(OUT): $(SRC) $(HDR)
	mkdir -p ../bin
	$(CC) -std=gnu17 -Wall -Wextra -Werror $(CFLAGS) -o $@ $(SRC)

check: $(OUT)
	sh selftest.sh $(OUT)
	sh selftest_shape.sh $(OUT)
	sh selftest-docs.sh $(OUT)
	sh selftest-safety.sh $(OUT)
	sh selftest-kpi.sh $(OUT)
	$(CC) -std=c2x -Wall -Wextra -Werror -fsyntax-only zcl-lint.c lintlib.c $(RULES)
	$(CC) -std=gnu17 -Wall -Wextra -Werror -o ../bin/lintlib-test lintlib_test.c lintlib.c && ../bin/lintlib-test

lint: $(OUT)
	$(OUT) --root ../.. all

clean:
	rm -f ../bin/zcl-lint ../bin/zcl-lint.exe

.PHONY: all check lint clean
