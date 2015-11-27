#pragma once

#ifndef _H_PLUG
#define _H_PLUG

namespace ExportHandlerID
{
	enum {
		SendDataHandler,
		ConnectToHandler,

		ExportHandlerCount
	};
}

typedef uint16_t plugin_id_type;

void plugin_init();
void set_method(const std::string& method, void* method_ptr);
void set_handler(unsigned int id, void* handler);
void* get_method(const char* method_name);
void* get_callback(plugin_id_type plugin_id, const char* name);
int load_plugin(const std::wstring &plugin_full_path);
bool plugin_check_id_type(uint16_t plugin_id, uint8_t type);
void plugin_on_data(int from, uint8_t type, const char* data, uint32_t length);

#endif
