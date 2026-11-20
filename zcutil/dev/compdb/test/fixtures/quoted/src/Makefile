all: q.o
q.o: q.cc
	g++ -DPACKAGE_STRING="\"x y\"" -DQ='a b' -DE=a\ b -c -o q.o q.cc
