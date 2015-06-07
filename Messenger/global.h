#pragma once

#ifndef _H_GLOB
#define _H_GLOB

struct user
{
	user(){ blockLast = -1; }
	int uID;
	wxIPV4address addr;
	wxSocketBase *con;
	CryptoPP::ECIES<CryptoPP::ECP>::Encryptor e1;

	wxString log;

	std::string recvFile;
	int blockLast;
};
typedef std::unordered_map<int, user> userList;

void insLen(std::string &data);
std::string num2str(long long n);

#endif