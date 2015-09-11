#include "stdafx.h"
#include "global.h"

void insLen(std::string &data)
{
	data_length_type len = boost::endian::native_to_little<data_length_type>(static_cast<data_length_type>(data.size()));
	data.insert(0, std::string(reinterpret_cast<const char*>(&len), sizeof(data_length_type)));
}

void ltrim(std::string &str)
{
	while (isspace(str.front()))
		str.erase(0, 1);
}

void rtrim(std::string &str)
{
	while (isspace(str.back()))
		str.pop_back();
}

void trim(std::string &str)
{
	ltrim(str);
	rtrim(str);
}
