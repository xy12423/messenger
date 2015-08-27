#include "stdafx.h"
#include "global.h"

void insLen(std::string &data)
{
	unsigned int len = wxUINT32_SWAP_ON_BE(static_cast<unsigned int>(data.size()));
	data.insert(0, std::string(reinterpret_cast<const char*>(&len), sizeof(unsigned int) / sizeof(char)));
}
