#pragma once

#include <cassert>
#include <cstdint>
#include <cstring>
#include <cstdlib>

#include <iostream>
#include <fstream>

#include <string>
#include <list>
#include <vector>
#include <unordered_map>

#include <algorithm>
#include <functional>
#include <limits>
#include <memory>
#include <utility>

#include <cryptopp/cryptlib.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/aes.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>
#include <cryptopp/modes.h>

#ifdef _MSC_VER
#pragma comment (lib, "cryptlib.lib")
#pragma comment (lib, "winmm.lib")
#pragma comment (lib, "wldap32.lib")
#pragma comment (lib, "comctl32.lib")
#pragma comment (lib, "rpcrt4.lib")
#pragma comment (lib, "odbc32.lib")
#endif

#if (!defined(WIN32)) && (defined(_WIN32) || defined(_WIN32_WINNT))
#define WIN32
#endif

#if (!defined(__linux__)) && (defined(__linux))
#define __linux__
#endif
