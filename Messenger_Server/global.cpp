#include "stdafx.h"
#include "global.h"

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
