CXX = g++
ifdef CLANG
  CXX = clang++
endif

objects = global.o crypto.o threads.o main.o
cppflag = -c -pthread --std=c++11 `wx-config --cppflags` -I/usr/local/include
lflag = `wx-config --libs` -L/usr/local/lib -lcryptopp -lboost_filesystem -lboost_system

ifdef RELEASE
  cppflag += -O2
else
  cppflag += -g3 -O0
endif

messenger : $(objects)
	$(CXX) $(objects) $(lflag) -o messenger
global.o : stdafx.h global.h global.cpp
	$(CXX) global.cpp $(cppflag) -o global.o
crypto.o : stdafx.h crypto.h crypto.cpp
	$(CXX) crypto.cpp $(cppflag) -o crypto.o
threads.o : stdafx.h global.h crypto.h threads.h threads.cpp
	$(CXX) threads.cpp $(cppflag) -o threads.o
main.o : stdafx.h global.h crypto.h threads.h main.h main.cpp
	$(CXX) main.cpp $(cppflag) -o main.o

clean:
	rm -rf *.o messenger
