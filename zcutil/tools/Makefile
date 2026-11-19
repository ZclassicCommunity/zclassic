# Build zcutil/bin/jsonq from the vendored Z23 sources (libc only, gnu17-clean).
#   make -C zcutil/tools                       host compiler
#   make -C zcutil/tools CC=x86_64-w64-mingw32-gcc EXEEXT=.exe
#   make -C zcutil/tools check                 run the jsonq fixture test
CC ?= cc
EXEEXT ?=
CFLAGS ?= -O2
V = vendor
INC = -I$(V)/tools -I$(V)/contexts/commons/packages/zjsonp/include \
      -I$(V)/contexts/commons/packages/zutf8/include
SRC = $(V)/tools/jsonq.c $(V)/tools/jsonq_standalone.c \
      $(V)/contexts/commons/packages/zjsonp/src/zjsonp.c \
      $(V)/contexts/commons/packages/zutf8/src/zutf8.c
OUT = ../bin/jsonq$(EXEEXT)

all: $(OUT)

$(OUT): $(SRC) $(V)/tools/multicall.h
	mkdir -p ../bin
	$(CC) -std=gnu17 -Wall -Wextra $(CFLAGS) $(INC) -o $@ $(SRC)

check: $(OUT)
	sh test-jsonq.sh $(OUT)

clean:
	rm -f ../bin/jsonq ../bin/jsonq.exe

.PHONY: all check clean
