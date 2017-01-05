#include "stdafx.h"
#include "crypto.h"

using namespace CryptoPP;
using namespace crypto;

void provider::genKey(const char* privatekeyFile)
{
	ECIES<ECP>::PrivateKey &privateKey = d0.AccessKey();
	privateKey.GenerateRandom(prng, MakeParameters(Name::GroupOID(), CURVE));
	FileSink fs(privatekeyFile, true);
	privateKey.Save(fs);
}

void provider::initKey(const char* privatekeyFile)
{
	ECIES<ECP>::PrivateKey &privateKey = d0.AccessKey();
	try
	{
		FileSource fs(privatekeyFile, true);
		privateKey.Load(fs);
		if (!privateKey.Validate(prng, 3))
			genKey(privatekeyFile);
	}
	catch (CryptoPP::FileStore::OpenErr &)
	{
		genKey(privatekeyFile);
	}
	dh_priv_block_size = dh.PrivateKeyLength();
	dh_pub_block_size = dh.PublicKeyLength();
	dh_agree_block_size = dh.AgreedValueLength();
}

const provider::asym_decryptor& provider::GetPublicKey()
{
	return d0;
}

std::string provider::GetPublicKeyString()
{
	std::string ret;
	StringSink buf(ret);
	asym_encryptor e0(d0);
	e0.GetPublicKey().Save(buf);

	return ret;
}

std::string provider::GetUserIDGlobal()
{
	std::string ret;
	StringSink buf(ret);
	asym_encryptor e0(d0);

	DL_PublicKey_EC<ECP>& key = dynamic_cast<DL_PublicKey_EC<ECP>&>(e0.AccessPublicKey());
	assert(&key != nullptr);

	key.DEREncodePublicKey(buf);
	assert(ret.front() == 4);
	ret.erase(0, 1);

	return ret;
}

void provider::encrypt(const std::string& src, std::string& dst, const asym_encryptor& e1)
{
	dst.clear();
	StringSource ss1(src, true, new PK_EncryptorFilter(prng, e1, new StringSink(dst)));
}

void provider::encrypt(const byte* src, size_t src_size, std::string& dst, const asym_encryptor& e1)
{
	dst.clear();
	StringSource ss1(src, src_size, true, new PK_EncryptorFilter(prng, e1, new StringSink(dst)));
}

void provider::decrypt(const std::string& src, std::string& dst, const asym_decryptor& _d0)
{
	dst.clear();
	StringSource ss1(src, true, new PK_DecryptorFilter(prng, _d0, new StringSink(dst)));
}

void provider::decrypt(const byte* src, size_t src_size, byte* dst, const asym_decryptor& _d0)
{
	_d0.Decrypt(prng, src, src_size, dst);
}

void provider::init_sym_encryption(sym_encryptor& e, const byte_block& key, byte_block& iv)
{
	assert(key.SizeInBytes() == sym_key_size);
	prng.GenerateBlock(iv, sym_key_size);
	e.SetKeyWithIV(key, sym_key_size, iv);
}

void provider::init_sym_decryption(sym_decryptor& d, const byte_block& key, const byte_block& iv)
{
	assert(key.SizeInBytes() == sym_key_size);
	assert(iv.SizeInBytes() == sym_key_size);
	d.SetKeyWithIV(key, sym_key_size, iv);
}

void provider::sym_encrypt(const std::string& src, std::string& dst, sym_encryptor& e)
{
	dst.clear();
	StringSource ss(src, true, new StreamTransformationFilter(e, new StringSink(dst)));
}

void provider::sym_decrypt(const std::string& src, std::string& dst, sym_decryptor& d)
{
	dst.clear();
	StringSource ss(src, true, new StreamTransformationFilter(d, new StringSink(dst)));
}

void provider::hash(const std::string& src, std::string& dst, size_t input_shift)
{
	SHA512 hasher;
	char result[hash_size];
	memset(result, 0, sizeof(result));
	hasher.CalculateDigest(reinterpret_cast<byte*>(result), reinterpret_cast<const byte*>(src.data()), src.size() - input_shift);
	dst.append(result, hash_size);
}

void provider::dhGen(byte_block& priv, byte_block& pub)
{
	dh.GenerateKeyPair(prng, priv, pub);
}

bool provider::dhAgree(byte_block& agree, const byte_block& priv, const byte_block& pub)
{
	SHA256 hasher;
	byte_block _agree(dh_agree_block_size);
	if (!dh.Agree(_agree, priv, pub))
		return false;
	assert(_agree.SizeInBytes() == dh_agree_block_size);
	hasher.CalculateDigest(agree, _agree, dh_agree_block_size);
	return true;
}

rand_num_type provider::genRandomNumber()
{
	rand_num_type t;
	prng.GenerateBlock(reinterpret_cast<byte*>(&t), sizeof(rand_num_type));
	return t;
}
