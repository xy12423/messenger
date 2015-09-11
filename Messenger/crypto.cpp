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

std::mutex enc_mutex;
void encrypt(const std::string &str, std::string &ret, ECIES<ECP>::Encryptor &e1)
{
	std::unique_lock<std::mutex> lck(enc_mutex);
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
	ECIES<ECP>::Encryptor e0(d0);
	e0.GetPublicKey().Save(buf);

	return ret;
}

void calcSHA256(const std::string &msg, std::string &ret, size_t input_shift)
{
	CryptoPP::SHA256 sha256;
	char result[sha256_size];
	memset(result, 0, sizeof(result));
	sha256.CalculateDigest(reinterpret_cast<byte*>(result), reinterpret_cast<const byte*>(msg.data() + input_shift), msg.size() - input_shift);
	ret.append(result, sha256_size);
}

rand_num_type genRandomNumber()
{
	return prng.GenerateWord32();
}
