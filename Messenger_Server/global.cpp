#include "stdafx.h"
#include "global.h"

void ltrim(std::string& str)
{
	if (str.empty())
		return;
	size_t pos = 0;
	std::string::iterator itr = str.begin(), itrEnd = str.end();
	for (; itr != itrEnd; itr++)
		if (!isspace(*itr))
			break;
	if (itr != itrEnd)
		str.erase(str.begin(), itr);
}

void rtrim(std::string& str)
{
	if (str.empty())
		return;
	while (isspace(str.back()))
		str.pop_back();
}

void trim(std::string& str)
{
	ltrim(str);
	rtrim(str);
}
