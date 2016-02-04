CXX = g++-5
ifdef CLANG
  CXX = clang++
endif

objects = global.o crypto.o session.o session_server.o main.o
cppflag = -g -c -o2 -pthread -I ~/boost -Wno-deprecated-declarations -std=c++14
lflag = -pthread -L ~/boost/stage/lib -lboost_filesystem-mt-s -lboost_system-mt-s -lcryptopp -lz -ldl -lm
messenger_server : $(objects)
	$(CXX) $(objects) $(lflag) -o messenger_server
global.o : stdafx.h global.h global.cpp
	$(CXX) global.cpp $(cppflag) -o global.o
crypto.o : stdafx.h crypto.h crypto.cpp
	$(CXX) crypto.cpp $(cppflag) -o crypto.o
session.o : stdafx.h crypto.h session.h session.cpp
	$(CXX) session.cpp $(cppflag) -o session.o
session_server.o : stdafx.h crypto.h session.h session_server.cpp
	$(CXX) session_server.cpp $(cppflag) -o session_server.o
main.o : stdafx.h global.h crypto.h session.h main.h main.cpp
	$(CXX) main.cpp $(cppflag) -o main.o

clean:
	rm -rf *.o messenger_server

