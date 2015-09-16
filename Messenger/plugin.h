#pragma once

#ifndef _H_PLUG
#define _H_PLUG

typedef uint8_t(*RegNextTypePtr)();
typedef void(*SendDataHandlerPtr)(int to, const char* data, size_t size);
typedef void(*SetSendDataHandlerPtr)(SendDataHandlerPtr handler);
typedef void(*cbOnDataPtr)(int from, uint8_t type, const char* data, const char* dataEnd);

bool load_plugin(const std::wstring &plugin_full_path);
void plugin_on_data(int from, uint8_t type, const char* data, const char* dataEnd);

#endif
