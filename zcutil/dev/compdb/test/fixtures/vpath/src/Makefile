all: here.o there.o
here.o:
	g++ -c -o here.o `test -f 'here.cc' || echo '../srcs/'`here.cc
there.o:
	g++ -DX -c -o there.o `test -f 'there.cc' || echo '../srcs/'`there.cc
