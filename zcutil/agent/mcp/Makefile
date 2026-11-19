# zcl-mcp: read-only MCP server for agents, plus zcl-run (Z23's process_group_exec, which bounds each
# tool call). Libc only; builds with the host cc, the mingw cross compiler and macOS clang.
# Output goes to ../../bin (git-ignored).
#   make -C zcutil/agent/mcp                                        host compiler
#   make -C zcutil/agent/mcp CC=x86_64-w64-mingw32-gcc EXEEXT=.exe  cross build
#   make -C zcutil/agent/mcp check                                  build, C2x compile check, scripted session
CC ?= cc
EXEEXT ?=
CFLAGS ?= -O2 -g
STD ?= -std=gnu17
WARN ?= -Wall -Wextra -Werror
V = ../../tools/vendor
INC = -I. -I$(V)/tools -I$(V)/platform/modules/json/include -I$(V)/platform/modules/base/include
BIN = ../../bin
VSRC = $(V)/tools/mcp/mcp_rpc.c $(V)/platform/modules/json/src/json.c \
       $(V)/platform/modules/base/src/safe_alloc.c $(V)/platform/modules/base/src/cleanse.c
ifneq ($(EXEEXT),)
CFLAGS += -D__USE_MINGW_ANSI_STDIO=1
endif

all: $(BIN)/zcl-mcp$(EXEEXT) $(BIN)/zcl-run$(EXEEXT)

$(BIN)/zcl-mcp$(EXEEXT): zcl-mcp.c tools.def $(VSRC)
	mkdir -p $(BIN)
	$(CC) $(STD) $(WARN) $(CFLAGS) $(INC) -o $@ zcl-mcp.c $(VSRC)

# The POSIX half of the upstream file relies on a C23 bool, hence -include stdbool.h (zcutil/tools/NOTICE).
$(BIN)/zcl-run$(EXEEXT): $(V)/tools/process_group_exec.c
	mkdir -p $(BIN)
	$(CC) $(STD) $(WARN) $(CFLAGS) -include stdbool.h -o $@ $<

# zcl-mcp must also compile as C2x (the language of Z23); no object is kept.
c2x:
	$(CC) -std=c2x $(WARN) $(CFLAGS) $(INC) -c -o /dev/null zcl-mcp.c

check: all c2x tools-built
	sh test/run.sh $(BIN)/zcl-mcp$(EXEEXT)

tools-built:
	$(MAKE) -C ../../tools all
	$(MAKE) -C ../../dev all
	$(MAKE) -C ../../dev/code all
	$(MAKE) -C ../../dev/wiki all
	$(MAKE) -C ../../dev/doctor all

clean:
	rm -f $(BIN)/zcl-mcp $(BIN)/zcl-mcp.exe $(BIN)/zcl-run $(BIN)/zcl-run.exe

.PHONY: all check clean c2x tools-built
