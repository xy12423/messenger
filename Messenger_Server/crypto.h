#pragma once

#ifndef _H_CRYP
#define _H_CRYP

typedef uint64_t rand_num_type;
const size_t hash_size = 64;

void genKey();
void initKey();

void encrypt(const std::string &str, std::string &ret, const CryptoPP::ECIES<CryptoPP::ECP>::Encryptor &e1);
void decrypt(const std::string &str, std::string &ret);
std::string getPublicKey();
std::string getUserIDGlobal();
void calcHash(const std::string &msg, std::string &ret, size_t input_shift = 0);
rand_num_type genRandomNumber();

#endif
