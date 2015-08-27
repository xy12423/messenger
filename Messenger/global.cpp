#include "stdafx.h"
#include "global.h"

void insLen(std::string &data)
{
	data_length_type len = wxUINT32_SWAP_ON_BE(static_cast<data_length_type>(data.size()));
	data.insert(0, std::string(reinterpret_cast<const char*>(&len), sizeof(data_length_type)));
}
