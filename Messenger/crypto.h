#pragma once

#ifndef _H_CRYP
#define _H_CRYP

typedef uint64_t rand_num_type;
const size_t hash_size = 64;

void genKey();
void initKey();

void encrypt(const std::string &src, std::string &dst, const CryptoPP::ECIES<CryptoPP::ECP>::Encryptor &e1);
void decrypt(const std::string &src, std::string &dst);
std::string getPublicKey();
std::string getUserIDGlobal();
void hash(const std::string &src, std::string &dst, size_t input_shift = 0);
rand_num_type genRandomNumber();

#endif
