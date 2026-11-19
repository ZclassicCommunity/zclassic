# One build and test entry for every developer tool under zcutil. All binaries land in
# zcutil/bin (git-ignored); generated documents go to zcutil/gen (git-ignored).
#   make -C zcutil                                        build everything with the host cc
#   make -C zcutil check                                  every tool's selftest
#   make -C zcutil CC=x86_64-w64-mingw32-gcc EXEEXT=.exe  cross build (every tool, zcl-lint included)
# A unit adds its own directory to SUBDIRS (one line); each subdirectory has its own Makefile
# with `all` and `check` targets, so units never share a source file.
EXEEXT ?=
SUBDIRS = tools dev dev/tests dev/hooks dev/code dev/wiki dev/doctor dev/gen agent/mcp agent/guard dev/verify lint

all check clean: $(SUBDIRS:%=%.rule)

# `check` builds every tool once, first and alone: some subdirectories' selftests run tools from other
# subdirectories (zcl-lint, zcl-dev), so under `make -j` they must not start while those still link.
ifneq ($(filter check,$(MAKECMDGOALS)),)
$(SUBDIRS:%=%.rule): built
endif
built:
	$(MAKE) all EXEEXT=$(EXEEXT)

# Pass `all`, `check` or `clean` through to each subdirectory, in order.
%.rule:
	$(MAKE) -C $* $(MAKECMDGOALS) EXEEXT=$(EXEEXT)

.PHONY: all check clean built
