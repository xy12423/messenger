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

void insLen(std::string &data);

#endif