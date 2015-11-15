CXX = g++-5
ifdef CLANG
  CXX = clang++
endif

objects = crypto.o session.o session_server.o threads.o plugin.o wx_srv_interface.o frmAddrInput.o main.o
wx_cppflag = `wx-config --cppflags`
cppflag = -c -o2 $(wx_cppflag) -pthread -I ~/boost -Wno-deprecated-declarations -std=c++14
wx_lflag = `wx-config --libs`
lflag = -pthread -L ~/boost/stage/lib $(wx_lflag) -lboost_filesystem-mt-s -lboost_system-mt-s -lcryptopp

ifdef RELEASE
  cppflag += -O2 -march=native -mtune=native
else
  cppflag += -g3 -O0
endif

ifdef NO_WARNING
  cppflag += -w
else
  ifdef CLANG
    cppflag += -Wno-potentially-evaluated-expression
  endif
endif

messenger : $(objects)
	$(CXX) $(objects) $(lflag) -o messenger
crypto.o : stdafx.h crypto.h crypto.cpp
	$(CXX) crypto.cpp $(cppflag) -o crypto.o
session.o : stdafx.h crypto.h session.h session.cpp
	$(CXX) session.cpp $(cppflag) -o session.o
session_server.o : stdafx.h crypto.h session.h session_server.cpp
	$(CXX) session_server.cpp $(cppflag) -o session_server.o
threads.o : stdafx.h crypto.h session.h threads.h threads.cpp
	$(CXX) threads.cpp $(cppflag) -o threads.o
plugin.o : stdafx.h plugin.h plugin.cpp
	$(CXX) plugin.cpp $(cppflag) -o plugin.o
wx_srv_interface.o : stdafx.h crypto.h session.h plugin.h main.h wx_srv_interface.cpp
	$(CXX) wx_srv_interface.cpp $(cppflag) -o wx_srv_interface.o
frmAddrInput.o : stdafx.h frmAddrInput.h frmAddrInput.cpp
	$(CXX) frmAddrInput.cpp $(cppflag) -o frmAddrInput.o
main.o : stdafx.h crypto.h session.h threads.h plugin.h main.h main.cpp
	$(CXX) main.cpp $(cppflag) -o main.o

clean:
	rm -rf *.o messenger
