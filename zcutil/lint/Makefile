# zcl-lint: ratchet gates (jq, bash, banned string functions, markdown links, vendored files).
#   make -C zcutil/lint              build ../bin/zcl-lint
#   make -C zcutil/lint check        selftest of every rule against fixture repositories
#   make -C zcutil/lint lint         run all rules on this tree (also: make -C src lint-fast)
CC ?= cc
EXEEXT ?=
CFLAGS ?= -O2
OUT = ../bin/zcl-lint$(EXEEXT)

all: $(OUT)

$(OUT): zcl-lint.c
	mkdir -p ../bin
	$(CC) -std=gnu17 -Wall -Wextra $(CFLAGS) -o $@ zcl-lint.c

check: $(OUT)
	sh selftest.sh $(OUT)

lint: $(OUT)
	$(OUT) --root ../.. all

clean:
	rm -f ../bin/zcl-lint ../bin/zcl-lint.exe

.PHONY: all check lint clean
