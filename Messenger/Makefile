objects = global.o crypto.o threads.o main.o
cppflag = -g -c -o2 -I/usr/local/lib/wx/include/gtk3-unicode-static-3.0 -I/usr/local/include/wx-3.0 -D_FILE_OFFSET_BITS=64 -D__WXGTK__ -pthread -I ~/boost -std=c++11
lflag = -L/usr/local/ssl/lib -L ~/boost/stage/lib -L/usr/local/lib -pthread   /usr/local/lib/libwx_gtk3u_xrc-3.0.a /usr/local/lib/libwx_gtk3u_qa-3.0.a /usr/local/lib/libwx_baseu_net-3.0.a /usr/local/lib/libwx_gtk3u_html-3.0.a /usr/local/lib/libwx_gtk3u_adv-3.0.a /usr/local/lib/libwx_gtk3u_core-3.0.a /usr/local/lib/libwx_baseu_xml-3.0.a /usr/local/lib/libwx_baseu-3.0.a -pthread -lgthread-2.0 -lX11 -lXxf86vm -lSM -lgtk-3 -lgdk-3 -latk-1.0 -lgio-2.0 -lpangocairo-1.0 -lgdk_pixbuf-2.0 -lcairo-gobject -lpango-1.0 -lcairo -lgobject-2.0 -lglib-2.0 -lpng -lexpat -lwxregexu-3.0 -lwxtiff-3.0 -lwxjpeg-3.0 -lboost_filesystem-mt-s -lboost_system-mt-s -lcryptopp -lz -ldl -lm
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

