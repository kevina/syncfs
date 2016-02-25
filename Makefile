CXX=g++ -std=gnu++0x
CXXFLAGS=-g -Wall
#CXXFLAGS=-O2 -Wall
#SSL=-DUSE_GNUTLS
SSL=-DUSE_OPENSSL

syncfs : syncfs.o remote.o drive.o
	${CXX} ${CXXFLAGS} -o syncfs syncfs.o remote.o drive.o `pkg-config fuse --libs` `curl-config --libs` -lsqlite3

syncfs.o : syncfs.cpp params.h remote.h sqlite3.hpp json.hpp
	${CXX} ${CXXFLAGS} `pkg-config fuse --cflags` -c syncfs.cpp

remote.o : remote.cpp remote.h json.hpp
	${CXX} ${CXXFLAGS} -c remote.cpp

drive.o: drive.cpp Makefile
	${CXX} ${CXXFLAGS} ${SSL} drive.cpp -c

clean:
	rm -f syncfs *.o

