#pragma once

#ifndef _H_GLOB
#define _H_GLOB

struct user
{
	user(){ lock = NULL; blockLast = -1; }
	int uID;
	net::ip::address addr;
	net::ip::tcp::socket *con;
	std::mutex *lock;
	CryptoPP::ECIES<CryptoPP::ECP>::Encryptor e1;

	std::string recvFile;
	int blockLast;
};
typedef std::unordered_map<int, user> userList;

void insLen(std::string &data);
std::string num2str(long long n);

#endif