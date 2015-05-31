#include "stdafx.h"
#include "global.h"

void insLen(std::string &data)
{
	unsigned int len = wxUINT32_SWAP_ON_BE(static_cast<unsigned int>(data.size()));
	data.insert(0, std::string(reinterpret_cast<const char*>(&len), sizeof(unsigned int) / sizeof(char)));
}

std::string num2str(long long n)
{
	static std::stringstream sstr;
	std::string ret;
	sstr.clear();
	sstr << n;
	sstr >> ret;
	return ret;
}
