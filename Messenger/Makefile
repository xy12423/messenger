objects = global.o crypto.o threads.o main.o
wx_cppflag = -I/usr/local/lib/wx/include/gtk2-unicode-static-3.0 -I/usr/local/include/wx-3.0 -D_FILE_OFFSET_BITS=64 -D__WXGTK__
cppflag = -g -c -o2 $(wx_cppflag) -pthread -I ~/boost -std=c++11
wx_lflag = -L/usr/local/lib -pthread /usr/local/lib/libwx_gtk2u_xrc-3.0.a /usr/local/lib/libwx_gtk2u_qa-3.0.a /usr/local/lib/libwx_baseu_net-3.0.a /usr/local/lib/libwx_gtk2u_html-3.0.a /usr/local/lib/libwx_gtk2u_adv-3.0.a /usr/local/lib/libwx_gtk2u_core-3.0.a /usr/local/lib/libwx_baseu_xml-3.0.a /usr/local/lib/libwx_baseu-3.0.a -pthread -lgthread-2.0 -lX11 -lXxf86vm -lSM -lgtk-x11-2.0 -lgdk-x11-2.0 -latk-1.0 -lgio-2.0 -lpangoft2-1.0 -lpangocairo-1.0 -lgdk_pixbuf-2.0 -lcairo -lpango-1.0 -lfontconfig -lgobject-2.0 -lglib-2.0 -lfreetype -lpng -lexpat -lwxregexu-3.0 -lwxtiff-3.0 -lwxjpeg-3.0
lflag = -L/usr/local/ssl/lib -L ~/boost/stage/lib $(wx_lflag) -lboost_filesystem-mt-s -lboost_system-mt-s -lcryptopp -lz -ldl -lm
messenger : $(objects)
	g++ $(objects) $(lflag) -o messenger
global.o : stdafx.h global.h global.cpp
	g++ global.cpp $(cppflag) -o global.o
crypto.o : stdafx.h crypto.h crypto.cpp
	g++ crypto.cpp $(cppflag) -o crypto.o
threads.o : stdafx.h global.h crypto.h threads.h threads.cpp
	g++ threads.cpp $(cppflag) -o threads.o
main.o : stdafx.h global.h crypto.h threads.h main.h main.cpp
	g++ main.cpp $(cppflag) -o main.o

