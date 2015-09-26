CXX = g++
ifdef CLANG
  CXX = clang++
endif

sources = $(wildcard ./*.cpp)
headers = $(wildcard ./*.h)
objects = $(sources:./%.cpp=%.o)
cppflag = -pthread --std=c++14 `wx-config --cppflags` -I/usr/local/include
ldflag = `wx-config --libs` -L/usr/local/lib -lcryptopp -lboost_filesystem -lboost_system

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
	$(CXX) $(objects) $(ldflag) -o messenger

./%.o: ./%.cpp
	$(CXX) $(cppflag) -c $< -o $@

clean:
	rm -rf *.o messenger
