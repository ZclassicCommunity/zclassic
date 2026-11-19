all: good.o s.o
good.o: good.cc
	g++ -c -o good.o good.cc
s.o: s.cc
	g++ -DV=$$(echo 1) -c -o s.o s.cc
