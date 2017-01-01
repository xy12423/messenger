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

const CryptoPP::ECIES<CryptoPP::ECP>::Decryptor& GetPublicKey()
{
	return d0;
}

std::string GetPublicKeyString()
{
	std::string ret;
	StringSink buf(ret);
	ECIES<ECP>::Encryptor e0(d0);
	e0.GetPublicKey().Save(buf);

	return ret;
}

std::string GetUserIDGlobal()
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

void encrypt(const std::string& src, std::string& dst, const ECIES<ECP>::Encryptor& e1)
{
	dst.clear();
	StringSource ss1(src, true, new PK_EncryptorFilter(prng, e1, new StringSink(dst)));
}

void encrypt(const byte* src, size_t src_size, std::string& dst, const CryptoPP::ECIES<CryptoPP::ECP>::Encryptor& e1)
{
	dst.clear();
	StringSource ss1(src, src_size, true, new PK_EncryptorFilter(prng, e1, new StringSink(dst)));
}

void decrypt(const std::string& src, std::string& dst, const CryptoPP::ECIES<CryptoPP::ECP>::Decryptor& _d0)
{
	dst.clear();
	StringSource ss1(src, true, new PK_DecryptorFilter(prng, _d0, new StringSink(dst)));
}

void decrypt(const byte* src, size_t src_size, CryptoPP::SecByteBlock& dst, const CryptoPP::ECIES<CryptoPP::ECP>::Decryptor& _d0)
{
	_d0.Decrypt(prng, src, src_size, dst);
}

void init_sym_encryption(CBC_Mode<AES>::Encryption& e, const SecByteBlock& key, SecByteBlock& iv)
{
	assert(key.SizeInBytes() == sym_key_size);
	prng.GenerateBlock(iv, sym_key_size);
	e.SetKeyWithIV(key, sym_key_size, iv);
}

void init_sym_decryption(CBC_Mode<AES>::Decryption& d, const SecByteBlock& key, const SecByteBlock& iv)
{
	assert(key.SizeInBytes() == sym_key_size);
	assert(iv.SizeInBytes() == sym_key_size);
	d.SetKeyWithIV(key, sym_key_size, iv);
}

void sym_encrypt(const std::string& src, std::string& dst, CBC_Mode<AES>::Encryption& e)
{
	dst.clear();
	StringSource ss(src, true, new StreamTransformationFilter(e, new StringSink(dst)));
}

void sym_decrypt(const std::string& src, std::string& dst, CBC_Mode<AES>::Decryption& d)
{
	dst.clear();
	StringSource ss(src, true, new StreamTransformationFilter(d, new StringSink(dst)));
}

void hash(const std::string& src, std::string& dst, size_t input_shift)
{
	CryptoPP::SHA512 hasher;
	char result[hash_size];
	memset(result, 0, sizeof(result));
	hasher.CalculateDigest(reinterpret_cast<byte*>(result), reinterpret_cast<const byte*>(src.data()), src.size() - input_shift);
	dst.append(result, hash_size);
}

void dhGen(SecByteBlock& priv, SecByteBlock& pub)
{
	dh.GenerateKeyPair(prng, priv, pub);
}

bool dhAgree(SecByteBlock& agree, const SecByteBlock& priv, const SecByteBlock& pub)
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
	rand_num_type t;
	prng.GenerateBlock(reinterpret_cast<byte*>(&t), sizeof(rand_num_type));
	return t;
}
