# One build and test entry for every developer tool under zcutil. All binaries land in
# zcutil/bin (git-ignored); generated documents go to zcutil/gen (git-ignored).
#   make -C zcutil                                        build everything with the host cc
#   make -C zcutil check                                  every tool's selftest
#   make -C zcutil CC=x86_64-w64-mingw32-gcc EXEEXT=.exe  cross build (zcl-lint is POSIX-only and skipped)
# A unit adds its own directory to SUBDIRS (one line); each subdirectory has its own Makefile
# with `all` and `check` targets, so units never share a source file.
EXEEXT ?=
SUBDIRS = tools dev dev/code dev/wiki dev/doctor dev/gen lint
ifneq ($(EXEEXT),)
SUBDIRS = tools dev dev/code dev/wiki dev/doctor dev/gen
endif

all check clean: $(SUBDIRS:%=%.rule)

# Pass `all`, `check` or `clean` through to each subdirectory, in order.
%.rule:
	$(MAKE) -C $* $(MAKECMDGOALS) EXEEXT=$(EXEEXT)

.PHONY: all check clean
