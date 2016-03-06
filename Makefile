CXX=g++ -std=gnu++0x
CXXFLAGS=-g -Wall -DDEBUG_LOCKS
#CXXFLAGS=-O2 -Wall
#SSL=-DUSE_GNUTLS
SSL=-DUSE_OPENSSL

syncfs : syncfs.o remote.o drive.o
	${CXX} ${CXXFLAGS} -o syncfs syncfs.o remote.o drive.o `pkg-config fuse --libs` `curl-config --libs` -lsqlite3

syncfs-gen.cpp: sqlite3-pp sqlite3-pp.pl syncfs.cpp
	./sqlite3-pp.pl

syncfs.o : syncfs-gen.cpp params.h remote.h sqlite3.hpp json.hpp
	${CXX} ${CXXFLAGS} `pkg-config fuse --cflags` -c syncfs-gen.cpp -o syncfs.o

remote.o : remote.cpp remote.h json.hpp
	${CXX} ${CXXFLAGS} -c remote.cpp

drive.o: drive.cpp Makefile
	${CXX} ${CXXFLAGS} ${SSL} drive.cpp -c

sqlite3-pp: sqlite3-pp.cpp
	${CXX} ${CXXFLAGS} sqlite3-pp.cpp -o sqlite3-pp

clean:
	rm -f syncfs *.o

