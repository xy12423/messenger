#include "stdafx.h"
#include "crypto.h"

using namespace CryptoPP;

AutoSeededRandomPool prng;
ECIES<ECP>::Decryptor d0;
extern const char* privatekeyFile;

void genKey()
{
	ECIES<ECP>::PrivateKey privateKey;
	privateKey.GenerateRandom(prng, MakeParameters(Name::GroupOID(), ASN1::secp521r1()));
	FileSink fs(privatekeyFile, true);
	privateKey.Save(fs);
	d0.AccessKey() = privateKey;
}

void initKey()
{
	ECIES<ECP>::PrivateKey privateKey;
	FileSource fs(privatekeyFile, true);
	privateKey.Load(fs);
	if (!privateKey.Validate(prng, 3))
		genKey();
	else
		d0.AccessKey() = privateKey;
}

void encrypt(const std::string &src, std::string &dst, const ECIES<ECP>::Encryptor &e1)
{
	dst.clear();
	StringSource ss1(src, true, new PK_EncryptorFilter(prng, e1, new StringSink(dst)));
}

void decrypt(const std::string &src, std::string &dst)
{
	dst.clear();
	StringSource ss1(src, true, new PK_DecryptorFilter(prng, d0, new StringSink(dst)));
}

std::string getPublicKey()
{
	std::string ret;
	StringSink buf(ret);
	ECIES<ECP>::Encryptor e0(d0);
	e0.GetPublicKey().Save(buf);

	return ret;
}

std::string getUserIDGlobal()
{
	std::string ret;
	StringSink buf(ret);
	ECIES<ECP>::Encryptor e0(d0);

	DL_PublicKey_EC<ECP>& key = dynamic_cast<DL_PublicKey_EC<ECP>&>(e0.AccessPublicKey());
	assert(&key != nullptr);

	key.DEREncodePublicKey(buf);
	assert(ret.front() == 4);
	ret.erase(0, 1);

	return ret;
}

void hash(const std::string &src, std::string &dst, size_t input_shift)
{
	CryptoPP::SHA512 hasher;
	char result[hash_size];
	memset(result, 0, sizeof(result));
	hasher.CalculateDigest(reinterpret_cast<byte*>(result), reinterpret_cast<const byte*>(src.data() + input_shift), src.size() - input_shift);
	dst.append(result, hash_size);
}

rand_num_type genRandomNumber()
{
	byte t[sizeof(rand_num_type)];
	prng.GenerateBlock(t, sizeof(rand_num_type));
	return *reinterpret_cast<rand_num_type*>(t);
}
