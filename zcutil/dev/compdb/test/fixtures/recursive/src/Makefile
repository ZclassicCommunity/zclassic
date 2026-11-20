all: top.o sub after.o
top.o: top.cc
	g++ -c -o top.o top.cc
after.o: after.cc
	g++ -c -o after.o after.cc
sub:
	$(MAKE) -C sub
.PHONY: sub
