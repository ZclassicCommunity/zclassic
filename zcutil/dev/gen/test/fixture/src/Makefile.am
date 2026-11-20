LIBFOO=libfoo.a
EXTRA_LIBRARIES += \
  $(LIBFOO) \
  libbar.a
bin_PROGRAMS =
if BUILD_DAEMON
  bin_PROGRAMS += fixd
endif

check-fixture:
	true
