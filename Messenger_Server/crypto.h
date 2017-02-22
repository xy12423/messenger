#pragma once

#ifndef _H_CRYP
#define _H_CRYP

typedef uint64_t rand_num_type;
static constexpr size_t hash_size = 64;
static constexpr size_t hash_short_size = 20;
static constexpr size_t sym_key_size = 32;

namespace crypto
{
	class provider
	{
	public:
		typedef CryptoPP::ECIES<CryptoPP::ECP>::Encryptor asym_encryptor;
		typedef CryptoPP::ECIES<CryptoPP::ECP>::Decryptor asym_decryptor;
		typedef CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption sym_encryptor;
		typedef CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption sym_decryptor;
		typedef CryptoPP::SecByteBlock byte_block;

		provider(const char* privatekeyFile) : CURVE(CryptoPP::ASN1::secp521r1()), prng(true), dh(CURVE) { initKey(privatekeyFile); }

		const asym_decryptor& GetPublicKey();
		std::string GetPublicKeyString();
		std::string GetUserIDGlobal();

		void encrypt(const std::string& src, std::string& dst, const asym_encryptor& e1);
		void encrypt(const byte* src, size_t src_size, std::string& dst, const asym_encryptor& e1);
		void decrypt(const std::string& src, std::string& dst, const asym_decryptor& d0);
		void decrypt(const byte* src, size_t src_size, std::string& dst, const asym_decryptor& d0);

		void init_sym_encryption(sym_encryptor& e, const byte_block& key, byte_block& iv);
		void init_sym_decryption(sym_decryptor& d, const byte_block& key, const byte_block& iv);
		void sym_encrypt(const std::string& src, std::string& dst, sym_encryptor& e);
		void sym_decrypt(const std::string& src, std::string& dst, sym_decryptor& d);

		void dhGen(byte_block& priv, byte_block& pub);
		bool dhAgree(byte_block& agree, const byte_block& priv, const byte_block& pub);

		rand_num_type genRandomNumber();

		static void hash(const std::string& src, std::string& dst, size_t input_shift = 0);
		static void hash_short(const std::string& src, std::string& dst);
		static void base32(std::string& ret, const byte* buf, size_t size);
		static void base32_rev(std::string& ret, const char* buf, size_t size);

		size_t dh_priv_block_size, dh_pub_block_size, dh_agree_block_size;
	private:
		void genKey(const char* privatekeyFile);
		void initKey(const char* privatekeyFile);

		const CryptoPP::OID CURVE;

		CryptoPP::AutoSeededRandomPool prng;
		CryptoPP::ECIES<CryptoPP::ECP>::Decryptor d0;
		CryptoPP::ECDH<CryptoPP::ECP>::Domain dh;
	};
}

#endif
