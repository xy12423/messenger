#pragma once

#ifndef _H_CRYP
#define _H_CRYP

typedef uint64_t rand_num_type;
const size_t hash_size = 64;
const size_t sym_key_length = 32;
extern size_t dh_priv_block_size, dh_pub_block_size, dh_agree_block_size;

void genKey();
void initKey();
std::string getPublicKey();
std::string getUserIDGlobal();

void encrypt(const std::string &src, std::string &dst, const CryptoPP::ECIES<CryptoPP::ECP>::Encryptor &e1);
void decrypt(const std::string &src, std::string &dst);
void hash(const std::string &src, std::string &dst, size_t input_shift = 0);

void init_sym_encryption(CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption &e, const CryptoPP::SecByteBlock &key, CryptoPP::SecByteBlock &iv);
void init_sym_decryption(CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption &d, const CryptoPP::SecByteBlock &key, const CryptoPP::SecByteBlock &iv);
void sym_encrypt(const std::string &src, std::string &dst, CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption &e);
void sym_decrypt(const std::string &src, std::string &dst, CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption &d);

void dhGen(CryptoPP::SecByteBlock &priv, CryptoPP::SecByteBlock &pub);
bool dhAgree(CryptoPP::SecByteBlock &agree, const  CryptoPP::SecByteBlock &priv, const  CryptoPP::SecByteBlock &pub);

rand_num_type genRandomNumber();

#endif
