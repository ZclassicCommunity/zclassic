# zcl-dev and zcl-port: developer tools. Libc only; builds with the host cc, the mingw cross
# compiler and macOS clang. Outputs go to ../bin (git-ignored).
#   make -C zcutil/dev                                        host compiler
#   make -C zcutil/dev CC=x86_64-w64-mingw32-gcc EXEEXT=.exe  cross build
#   make -C zcutil/dev check                                  build and run the fixture tests
CC ?= cc
EXEEXT ?=
CFLAGS ?= -O2 -g
STD ?= -std=gnu17
WARN ?= -Wall -Wextra -Werror
INC = -I../tools/vendor
HDR = ../tools/vendor/platform/modules/platform/include/platform/glob_match.h
BIN = ../bin
LDLIBS_PORT =
ifneq ($(EXEEXT),)
LDLIBS_PORT = -lws2_32
CFLAGS += -D__USE_MINGW_ANSI_STDIO=1
endif

all: $(BIN)/zcl-dev$(EXEEXT) $(BIN)/zcl-port$(EXEEXT)

$(BIN)/zcl-dev$(EXEEXT): zcl-dev.c $(HDR)
	mkdir -p $(BIN)
	$(CC) $(STD) $(WARN) $(CFLAGS) $(INC) -o $@ zcl-dev.c

$(BIN)/zcl-port$(EXEEXT): zcl-port.c
	mkdir -p $(BIN)
	$(CC) $(STD) $(WARN) $(CFLAGS) -o $@ zcl-port.c $(LDLIBS_PORT)

check: $(BIN)/zcl-dev$(EXEEXT)
	sh test/run.sh $(BIN)/zcl-dev$(EXEEXT)
	sh test/dispatch.sh $(BIN)/zcl-dev$(EXEEXT)
	sh test/ci-receipts.sh $(BIN)/zcl-dev$(EXEEXT)
	$(BIN)/zcl-dev$(EXEEXT) check-rules
	$(BIN)/zcl-dev$(EXEEXT) check-docs

clean:
	rm -f $(BIN)/zcl-dev $(BIN)/zcl-dev.exe $(BIN)/zcl-port $(BIN)/zcl-port.exe

.PHONY: all check clean
