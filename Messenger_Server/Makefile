CXX = g++-5
ifdef CLANG
  CXX = clang++
endif

objects = global.o crypto.o crypto_man.o session.o session_server.o plugin.o main.o
cppflag = -c -pthread -I ~/boost -Wno-deprecated-declarations -std=c++14
lflag = -pthread -L ~/boost/stage/lib -lboost_filesystem -lboost_system -lcryptopp

ifdef RELEASE
  cppflag += -g0 -O2 -DNDEBUG
else
  cppflag += -g3 -O0 -D_DEBUG
endif

messenger_server : $(objects)
	$(CXX) $(objects) $(lflag) -o messenger_server
global.o : stdafx.h global.h global.cpp
	$(CXX) global.cpp $(cppflag) -o global.o
crypto.o : stdafx.h crypto.h crypto.cpp
	$(CXX) crypto.cpp $(cppflag) -o crypto.o
crypto_man.o : stdafx.h crypto.h crypto_man.h crypto_man.cpp
	$(CXX) crypto_man.cpp $(cppflag) -o crypto_man.o
session.o : stdafx.h crypto.h session.h session.cpp
	$(CXX) session.cpp $(cppflag) -o session.o
session_server.o : stdafx.h crypto.h session.h session_server.cpp
	$(CXX) session_server.cpp $(cppflag) -o session_server.o
plugin.o : stdafx.h global.h crypto.h session.h plugin.h plugin.cpp
	$(CXX) plugin.cpp $(cppflag) -o plugin.o
main.o : stdafx.h global.h crypto.h session.h plugin.h main.h main.cpp
	$(CXX) main.cpp $(cppflag) -o main.o

clean:
	rm -rf *.o messenger_server
