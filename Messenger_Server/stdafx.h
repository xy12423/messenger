#pragma once

#include <iostream>
#include <fstream>
#include <sstream>
#include <cstdint>
#include <cstring>
#include <cctype>
#include <climits>
#include <cstdlib>
#include <ctime>
#include <string>
#include <list>
#include <vector>
#include <set>
#include <map>
#include <unordered_set>
#include <unordered_map>
#include <algorithm>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>

#include <boost/filesystem.hpp>
#include <boost/asio.hpp>
#include <boost/endian/conversion.hpp>
namespace fs = boost::filesystem;
namespace net = boost::asio;

#include <cryptopp/cryptlib.h>
#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>
#include <cryptopp/asn.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/files.h>

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
