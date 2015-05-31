#include "stdafx.h"
#include "crypto.h"

using namespace CryptoPP;

AutoSeededRandomPool prng;
ECIES<ECP>::Decryptor d0(prng, ASN1::secp521r1());
ECIES<ECP>::Encryptor e0(d0);

void encrypt(const std::string &str, std::string &ret, ECIES<ECP>::Encryptor &e1)
{
	ret.clear();
	StringSource ss1(str, true, new PK_EncryptorFilter(prng, e1, new StringSink(ret)));
}

void decrypt(const std::string &str, std::string &ret)
{
	ret.clear();
	StringSource ss1(str, true, new PK_DecryptorFilter(prng, d0, new StringSink(ret)));
}

std::string getPublicKey()
{
	std::string ret;
	StringSinkTemplate<std::string> buf(ret);
	e0.GetPublicKey().Save(buf);
	return ret;
}
