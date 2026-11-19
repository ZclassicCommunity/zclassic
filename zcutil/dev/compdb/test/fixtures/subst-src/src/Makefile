all: good.o s.o
good.o: good.cc
	g++ -c -o good.o good.cc
s.o:
	g++ -DV=1 -c -o s.o `echo s.cc`
