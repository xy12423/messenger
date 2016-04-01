#include "stdafx.h"
#include "crypto.h"

using namespace CryptoPP;

const OID CURVE = ASN1::secp521r1();

AutoSeededRandomPool prng;
ECIES<ECP>::Decryptor d0;
ECDH<ECP>::Domain dh(CURVE);
extern const char* privatekeyFile;
size_t dh_priv_block_size, dh_pub_block_size, dh_agree_block_size;

void genKey()
{
	ECIES<ECP>::PrivateKey &privateKey = d0.AccessKey();
	privateKey.GenerateRandom(prng, MakeParameters(Name::GroupOID(), CURVE));
	FileSink fs(privatekeyFile, true);
	privateKey.Save(fs);
}

void initKey()
{
	ECIES<ECP>::PrivateKey &privateKey = d0.AccessKey();
	try
	{
		FileSource fs(privatekeyFile, true);
		privateKey.Load(fs);
		if (!privateKey.Validate(prng, 3))
			genKey();
	}
	catch (CryptoPP::FileStore::OpenErr &)
	{
		genKey();
	}
	dh_priv_block_size = dh.PrivateKeyLength();
	dh_pub_block_size = dh.PublicKeyLength();
	dh_agree_block_size = dh.AgreedValueLength();
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

void init_sym_encryption(CBC_Mode<AES>::Encryption &e, const SecByteBlock &key, SecByteBlock &iv)
{
	assert(key.SizeInBytes() == sym_key_length);
	prng.GenerateBlock(iv, sym_key_length);
	e.SetKeyWithIV(key, sym_key_length, iv);
}

void init_sym_decryption(CBC_Mode<AES>::Decryption &d, const SecByteBlock &key, const SecByteBlock &iv)
{
	assert(key.SizeInBytes() == sym_key_length);
	assert(iv.SizeInBytes() == sym_key_length);
	d.SetKeyWithIV(key, sym_key_length, iv);
}

void sym_encrypt(const std::string &src, std::string &dst, CBC_Mode<AES>::Encryption &e)
{
	dst.clear();
	StringSource ss(src, true, new StreamTransformationFilter(e, new StringSink(dst)));
}

void sym_decrypt(const std::string &src, std::string &dst, CBC_Mode<AES>::Decryption &d)
{
	dst.clear();
	StringSource ss(src, true, new StreamTransformationFilter(d, new StringSink(dst)));
}

void hash(const std::string &src, std::string &dst, size_t input_shift)
{
	CryptoPP::SHA512 hasher;
	char result[hash_size];
	memset(result, 0, sizeof(result));
	hasher.CalculateDigest(reinterpret_cast<byte*>(result), reinterpret_cast<const byte*>(src.data()), src.size() - input_shift);
	dst.append(result, hash_size);
}

void dhGen(SecByteBlock &priv, SecByteBlock &pub)
{
	dh.GenerateKeyPair(prng, priv, pub);
}

bool dhAgree(SecByteBlock &agree, const SecByteBlock &priv, const SecByteBlock &pub)
{
	CryptoPP::SHA256 hasher;
	SecByteBlock _agree(dh_agree_block_size);
	if (!dh.Agree(_agree, priv, pub))
		return false;
	assert(_agree.SizeInBytes() == dh_agree_block_size);
	hasher.CalculateDigest(agree, _agree, dh_agree_block_size);
	return true;
}

rand_num_type genRandomNumber()
{
	byte t[sizeof(rand_num_type)];
	prng.GenerateBlock(t, sizeof(rand_num_type));
	return *reinterpret_cast<rand_num_type*>(t);
}
