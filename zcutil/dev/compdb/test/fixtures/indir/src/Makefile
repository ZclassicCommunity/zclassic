all: a.o z.o
a.o: a.cc
	g++ -DFOO=1 -I. -MT a.o -MD -MP -MF .deps/a.Tpo -c -o a.o a.cc
z.o: z.c
	gcc -O2 -c -o z.o z.c
