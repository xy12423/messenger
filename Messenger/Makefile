objects = crypto.o crypto_man.o session.o session_server.o threads.o plugin.o wx_srv_interface.o frmAddrInput.o main.o
wx_cppflag = `wx-config --cppflags std,richtext`
wx_lflag = `wx-config --libs std,richtext`

ifeq ($(shell sh -c 'uname -s'), Darwin)
    cppflag = -c $(wx_cppflag) -I /usr/local/include -Wno-deprecated-declarations -std=c++14
    lflag = -lpthread -L /usr/local/lib $(wx_lflag) -lboost_filesystem-mt -lboost_system-mt -lcryptopp
    CXX = clang++
else
    cppflag = -c $(wx_cppflag) -pthread -I ~/boost -Wno-deprecated-declarations -std=c++14
    lflag = -pthread -L ~/boost/stage/lib $(wx_lflag) -lboost_filesystem -lboost_system -lcryptopp -static-libstdc++
    CXX = g++
endif

ifeq ($(RELEASE), 1)
    cppflag += -O2 -g0 -DNDEBUG
else
    cppflag += -O0 -g3 -D_DEBUG
endif

ifeq ($(NOWARNING), 1)
    cppflag += -w
endif

all: messenger

messenger : $(objects)
	$(CXX) $(objects) $(lflag) -o messenger
crypto.o : stdafx.h crypto.h crypto.cpp
	$(CXX) crypto.cpp $(cppflag) -o crypto.o
crypto_man.o : stdafx.h crypto.h crypto_man.h crypto_man.cpp
	$(CXX) crypto_man.cpp $(cppflag) -o crypto_man.o
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
