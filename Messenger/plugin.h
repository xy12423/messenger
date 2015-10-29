#pragma once

#ifndef _H_PLUG
#define _H_PLUG

void set_method(const std::string& method, void* method_ptr);
bool load_plugin(const std::wstring &plugin_full_path);
void plugin_on_data(int from, uint8_t type, const char* data, const char* dataEnd);

#endif
