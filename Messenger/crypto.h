#pragma once

#ifndef _H_CRYP
#define _H_CRYP

void genKey();
void initKey();

void encrypt(const std::string &str, std::string &ret, CryptoPP::ECIES<CryptoPP::ECP>::Encryptor &e1);
void decrypt(const std::string &str, std::string &ret);
std::string getPublicKey();

#endif
