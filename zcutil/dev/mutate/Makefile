# zcl-dev-mutate: mutation testing for one C or C++ file (`zcl-dev mutate`). Libc only; builds with the
# host cc, clang and the mingw cross compiler (on Windows only `list` works). Output goes to ../../bin.
#   make -C zcutil/dev/mutate [CC=x86_64-w64-mingw32-gcc EXEEXT=.exe]    build
#   make -C zcutil/dev/mutate check      --selftest, c2x and the fixture tests (POSIX; UPDATE=1 rewrites goldens)
CC ?= cc
EXEEXT ?=
CFLAGS ?= -O2 -g
STD ?= -std=gnu17
WARN ?= -Wall -Wextra -Werror
BIN = ../../bin
SRC = zcl-dev-mutate.c mutate_ops.c mutate_run.c
HDR = mutate_ops.h
ifneq ($(EXEEXT),)
CFLAGS += -D__USE_MINGW_ANSI_STDIO=1
endif
TOOL = $(BIN)/zcl-dev-mutate$(EXEEXT)
# The fixture driver is not a zcl-dev subcommand, so it lives in the ignored zcutil/gen, not in bin.
TEST = ../../gen/mutate-test/mutate_test

all: $(TOOL)

$(TOOL): $(SRC) $(HDR)
	mkdir -p $(BIN)
	$(CC) $(STD) $(WARN) $(CFLAGS) -o $@ $(SRC)

$(TEST): test/mutate_test.c
	mkdir -p ../../gen/mutate-test
	$(CC) $(STD) $(WARN) $(CFLAGS) -o $@ test/mutate_test.c

check: $(TOOL) $(TEST)
	$(TOOL) --selftest
	$(MAKE) -s c2x
	$(TEST) $(TOOL) test

# Every file also compiles as C23 (a syntax check only).
c2x: $(SRC) $(HDR) test/mutate_test.c
	for f in $(SRC) test/mutate_test.c; do $(CC) -std=c2x $(WARN) -fsyntax-only $$f || exit 1; done

clean:
	rm -f $(BIN)/zcl-dev-mutate $(BIN)/zcl-dev-mutate.exe $(TEST)

.PHONY: all check c2x clean
