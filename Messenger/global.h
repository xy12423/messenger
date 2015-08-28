#pragma once

#ifndef _H_GLOB
#define _H_GLOB

struct user_ext_data
{
	std::wstring addr;
	wxString log;

	std::string recvFile;
	int blockLast;
};

typedef uint16_t key_length_type;
typedef uint32_t data_length_type;
void insLen(std::string &data);

#endif
