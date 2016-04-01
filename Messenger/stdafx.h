#pragma once

#include <cassert>
#include <cstdint>
#include <cstring>
#include <cctype>
#include <climits>
#include <cstdlib>
#include <ctime>

#include <iostream>
#include <fstream>
#include <sstream>

#include <string>
#include <list>
#include <vector>
#include <set>
#include <map>
#include <unordered_set>
#include <unordered_map>

#include <algorithm>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <utility>

#include <boost/filesystem.hpp>
#include <boost/asio.hpp>
#include <boost/endian/conversion.hpp>
namespace fs = boost::filesystem;
namespace asio = boost::asio;

#include <cryptopp/cryptlib.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/aes.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>
#include <cryptopp/modes.h>

#include <wx/platform.h>
#include <wx/wxprec.h>
#ifndef WX_PRECOMP
#	include <wx/wx.h>
#endif
#include <wx/mstream.h>
#include <wx/richtext/richtextctrl.h>
#include <wx/dynlib.h>
#ifdef _MSC_VER
#	ifdef _DEBUG
#		pragma comment (lib, "wxbase31ud.lib")
#		pragma comment (lib, "wxbase31ud_net.lib")
#		pragma comment (lib, "wxbase31ud_xml.lib")
#		pragma comment (lib, "wxmsw31ud_adv.lib")
#		pragma comment (lib, "wxmsw31ud_aui.lib")
#		pragma comment (lib, "wxmsw31ud_core.lib")
#		pragma comment (lib, "wxmsw31ud_gl.lib")
#		pragma comment (lib, "wxmsw31ud_html.lib")
#		pragma comment (lib, "wxmsw31ud_media.lib")
#		pragma comment (lib, "wxmsw31ud_propgrid.lib")
#		pragma comment (lib, "wxmsw31ud_qa.lib")
#		pragma comment (lib, "wxmsw31ud_ribbon.lib")
#		pragma comment (lib, "wxmsw31ud_richtext.lib")
#		pragma comment (lib, "wxmsw31ud_stc.lib")
#		pragma comment (lib, "wxmsw31ud_webview.lib")
#		pragma comment (lib, "wxmsw31ud_xrc.lib")
#		pragma comment (lib, "wxexpatd.lib")
#		pragma comment (lib, "wxjpegd.lib")
#		pragma comment (lib, "wxpngd.lib")
#		pragma comment (lib, "wxregexud.lib")
#		pragma comment (lib, "wxscintillad.lib")
#		pragma comment (lib, "wxtiffd.lib")
#		pragma comment (lib, "wxzlibd.lib")
#	else
#		pragma comment (lib, "wxbase31u.lib")
#		pragma comment (lib, "wxbase31u_net.lib")
#		pragma comment (lib, "wxbase31u_xml.lib")
#		pragma comment (lib, "wxmsw31u_adv.lib")
#		pragma comment (lib, "wxmsw31u_aui.lib")
#		pragma comment (lib, "wxmsw31u_core.lib")
#		pragma comment (lib, "wxmsw31u_gl.lib")
#		pragma comment (lib, "wxmsw31u_html.lib")
#		pragma comment (lib, "wxmsw31u_media.lib")
#		pragma comment (lib, "wxmsw31u_propgrid.lib")
#		pragma comment (lib, "wxmsw31u_qa.lib")
#		pragma comment (lib, "wxmsw31u_ribbon.lib")
#		pragma comment (lib, "wxmsw31u_richtext.lib")
#		pragma comment (lib, "wxmsw31u_stc.lib")
#		pragma comment (lib, "wxmsw31u_webview.lib")
#		pragma comment (lib, "wxmsw31u_xrc.lib")
#		pragma comment (lib, "wxexpat.lib")
#		pragma comment (lib, "wxjpeg.lib")
#		pragma comment (lib, "wxpng.lib")
#		pragma comment (lib, "wxregexu.lib")
#		pragma comment (lib, "wxscintilla.lib")
#		pragma comment (lib, "wxtiff.lib")
#		pragma comment (lib, "wxzlib.lib")
#	endif
#endif

#ifdef _MSC_VER
#ifdef _DEBUG
#pragma comment (lib, "zlibd.lib")
#pragma comment (lib, "cryptlibd.lib")
#else
#pragma comment (lib, "zlib.lib")
#pragma comment (lib, "cryptlib.lib")
#endif
#pragma comment (lib, "ws2_32.lib")
#pragma comment (lib, "winmm.lib")
#pragma comment (lib, "wldap32.lib")
#pragma comment (lib, "comctl32.lib")
#pragma comment (lib, "rpcrt4.lib")
#pragma comment (lib, "wsock32.lib")
#pragma comment (lib, "odbc32.lib")
#endif

#if (!defined(WIN32)) && (defined(_WIN32) || defined(_WIN32_WINNT))
#define WIN32
#endif

#if (!defined(__linux__)) && (defined(__linux))
#define __linux__
#endif
