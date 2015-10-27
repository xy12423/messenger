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
namespace net = boost::asio;

#include <cryptopp/cryptlib.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>

#include <wx/platform.h>
#include <wx/wxprec.h>
#ifndef WX_PRECOMP
#	include <wx/wx.h>
#endif
#include <wx/msgqueue.h>
#include <wx/dynlib.h>
#ifdef _MSC_VER
#	ifdef _DEBUG
#		pragma comment (lib, "wxbase30ud.lib")
#		pragma comment (lib, "wxbase30ud_net.lib")
#		pragma comment (lib, "wxbase30ud_xml.lib")
#		pragma comment (lib, "wxmsw30ud_adv.lib")
#		pragma comment (lib, "wxmsw30ud_aui.lib")
#		pragma comment (lib, "wxmsw30ud_core.lib")
#		pragma comment (lib, "wxmsw30ud_gl.lib")
#		pragma comment (lib, "wxmsw30ud_html.lib")
#		pragma comment (lib, "wxmsw30ud_media.lib")
#		pragma comment (lib, "wxmsw30ud_propgrid.lib")
#		pragma comment (lib, "wxmsw30ud_qa.lib")
#		pragma comment (lib, "wxmsw30ud_ribbon.lib")
#		pragma comment (lib, "wxmsw30ud_richtext.lib")
#		pragma comment (lib, "wxmsw30ud_stc.lib")
#		pragma comment (lib, "wxmsw30ud_xrc.lib")
#		pragma comment (lib, "wxscintillad.lib")
#		pragma comment (lib, "wxbase30ud.lib")
#		pragma comment (lib, "wxtiffd.lib")
#		pragma comment (lib, "wxjpegd.lib")
#		pragma comment (lib, "wxpngd.lib")
#	else
#		pragma comment (lib, "wxbase30u.lib")
#		pragma comment (lib, "wxbase30u_net.lib")
#		pragma comment (lib, "wxbase30u_xml.lib")
#		pragma comment (lib, "wxmsw30u_adv.lib")
#		pragma comment (lib, "wxmsw30u_aui.lib")
#		pragma comment (lib, "wxmsw30u_core.lib")
#		pragma comment (lib, "wxmsw30u_gl.lib")
#		pragma comment (lib, "wxmsw30u_html.lib")
#		pragma comment (lib, "wxmsw30u_media.lib")
#		pragma comment (lib, "wxmsw30u_propgrid.lib")
#		pragma comment (lib, "wxmsw30u_qa.lib")
#		pragma comment (lib, "wxmsw30u_ribbon.lib")
#		pragma comment (lib, "wxmsw30u_richtext.lib")
#		pragma comment (lib, "wxmsw30u_stc.lib")
#		pragma comment (lib, "wxmsw30u_xrc.lib")
#		pragma comment (lib, "wxscintilla.lib")
#		pragma comment (lib, "wxbase30u.lib")
#		pragma comment (lib, "wxtiff.lib")
#		pragma comment (lib, "wxjpeg.lib")
#		pragma comment (lib, "wxpng.lib")
#	endif
#endif

#ifdef _MSC_VER
#ifdef _DEBUG
#pragma comment (lib, "zlibd-mt.lib")
#pragma comment (lib, "cryptlibd-mt.lib")
#else
#pragma comment (lib, "zlib-mt.lib")
#pragma comment (lib, "cryptlib-mt.lib")
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
