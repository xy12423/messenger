objects = utils.o crypto.o session.o main.o
cppflag = -g -c -o2 -pthread -I ~/boost -std=c++11
lflag = -L ~/boost/stage/lib -lboost_filesystem-mt-s -lboost_system-mt-s -lcryptopp -lz -ldl -lm
messenger_server : $(objects)
	g++ $(objects) $(lflag) -o messenger_server
utils.o : stdafx.h utils.h utils.cpp
	g++ utils.cpp $(cppflag) -o utils.o
crypto.o : stdafx.h crypto.h crypto.cpp
	g++ crypto.cpp $(cppflag) -o crypto.o
session.o : stdafx.h crypto.h utils.h main.h session.cpp
	g++ session.cpp $(cppflag) -o session.o
main.o : stdafx.h crypto.h utils.h main.h main.cpp
	g++ main.cpp $(cppflag) -o main.o


