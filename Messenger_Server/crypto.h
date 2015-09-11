#pragma once

#ifndef _H_CRYP
#define _H_CRYP

typedef uint32_t rand_num_type;
const size_t sha256_size = 32;

void genKey();
void initKey();

void encrypt(const std::string &str, std::string &ret, CryptoPP::ECIES<CryptoPP::ECP>::Encryptor &e1);
void decrypt(const std::string &str, std::string &ret);
std::string getPublicKey();
void calcSHA256(const std::string &msg, std::string &ret, int input_shift = 0);
rand_num_type genRandomNumber();

#endif
