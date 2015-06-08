#include "stdafx.h"
#include "utils.h"

void insLen(std::string &data)
{
	unsigned int len = static_cast<unsigned int>(data.size());
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
