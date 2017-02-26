#pragma once

#ifndef _H_GLOB
#define _H_GLOB

enum pac_type {
	PAC_TYPE_MSG,
	PAC_TYPE_FILE_H,
	PAC_TYPE_FILE_B,
	PAC_TYPE_IMAGE,
	PAC_TYPE_PLUGIN_FLAG,
	PAC_TYPE_PLUGIN_DATA,
};

void ltrim(std::string& str);
void rtrim(std::string& str);
void trim(std::string& str);

#endif
