# zcl-doctor: host readiness check. Libc only; host cc, clang or the mingw cross compiler.
# It also builds alone: cc -std=gnu17 -o zcl-doctor zcl-doctor.c
#   make -C zcutil/dev/doctor [CC=x86_64-w64-mingw32-gcc EXEEXT=.exe]    build into ../../bin
#   make -C zcutil/dev/doctor check                                      --selftest and the golden tests
CC ?= cc
EXEEXT ?=
CFLAGS ?= -O2 -g
STD ?= -std=gnu17
WARN ?= -Wall -Wextra -Werror
BIN = ../../bin
ifneq ($(EXEEXT),)
CFLAGS += -D__USE_MINGW_ANSI_STDIO=1
endif
TOOL = $(BIN)/zcl-dev-doctor$(EXEEXT)

all: $(TOOL)

$(TOOL): zcl-doctor.c
	mkdir -p $(BIN)
	$(CC) $(STD) $(WARN) $(CFLAGS) -o $@ zcl-doctor.c

check: $(TOOL)
	$(TOOL) --selftest
	sh test/run.sh $(TOOL)

clean:
	rm -f $(BIN)/zcl-dev-doctor $(BIN)/zcl-dev-doctor.exe

.PHONY: all check clean
