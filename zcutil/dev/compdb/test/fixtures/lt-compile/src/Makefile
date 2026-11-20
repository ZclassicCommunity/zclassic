all: a.lo
a.lo: a.cc
	depbase=`echo a.lo | sed 's|[^/]*$$||'`;\
	/bin/sh ./libtool --tag=CXX --mode=compile g++ -DHAVE_CONFIG_H -MT a.lo -MD -MP -MF $$depbase.Tpo -c -o a.lo a.cc &&\
	mv -f $$depbase.Tpo $$depbase.Plo
