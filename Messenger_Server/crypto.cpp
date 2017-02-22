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

void provider::decrypt(const byte* src, size_t src_size, std::string& dst, const asym_decryptor& _d0)
{
	dst.clear();
	StringSource ss1(src, src_size, true, new PK_DecryptorFilter(prng, _d0, new StringSink(dst)));
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

void provider::base32(std::string& ret, const byte* buf, size_t size)
{
	static const char encode32[] = "ABCDEFGHIJKLMNPQRSTUVWXYZ1234567";
	constexpr char space32 = '0';

	const byte *ptr_end = buf + size - 5;
	const byte *ptr = buf;
	for (; ptr < ptr_end; ptr += 5)
	{
		ret.push_back(encode32[ptr[0] >> 3]);
		ret.push_back(encode32[((ptr[0] << 2) | (ptr[1] >> 6)) & 0x1F]);
		ret.push_back(encode32[(ptr[1] >> 1) & 0x1F]);
		ret.push_back(encode32[((ptr[1] << 4) | (ptr[2] >> 4)) & 0x1F]);
		ret.push_back(encode32[((ptr[2] << 1) | (ptr[3] >> 7)) & 0x1F]);
		ret.push_back(encode32[(ptr[3] >> 2) & 0x1F]);
		ret.push_back(encode32[((ptr[3] << 3) | (ptr[4] >> 5)) & 0x1F]);
		ret.push_back(encode32[ptr[4] & 0x1F]);
	}
	switch (ptr - ptr_end)
	{
		case 0:
			ret.push_back(encode32[ptr[0] >> 3]);
			ret.push_back(encode32[((ptr[0] << 2) | (ptr[1] >> 6)) & 0x1F]);
			ret.push_back(encode32[(ptr[1] >> 1) & 0x1F]);
			ret.push_back(encode32[((ptr[1] << 4) | (ptr[2] >> 4)) & 0x1F]);
			ret.push_back(encode32[((ptr[2] << 1) | (ptr[3] >> 7)) & 0x1F]);
			ret.push_back(encode32[(ptr[3] >> 2) & 0x1F]);
			ret.push_back(encode32[((ptr[3] << 3) | (ptr[4] >> 5)) & 0x1F]);
			ret.push_back(encode32[ptr[4] & 0x1F]);
			break;
		case 1:
			ret.push_back(encode32[ptr[0] >> 3]);
			ret.push_back(encode32[((ptr[0] << 2) | (ptr[1] >> 6)) & 0x1F]);
			ret.push_back(encode32[(ptr[1] >> 1) & 0x1F]);
			ret.push_back(encode32[((ptr[1] << 4) | (ptr[2] >> 4)) & 0x1F]);
			ret.push_back(encode32[((ptr[2] << 1) | (ptr[3] >> 7)) & 0x1F]);
			ret.push_back(encode32[(ptr[3] >> 2) & 0x1F]);
			ret.push_back(encode32[(ptr[3] << 3) & 0x1F]);
			ret.push_back(space32);
			break;
		case 2:
			ret.push_back(encode32[ptr[0] >> 3]);
			ret.push_back(encode32[((ptr[0] << 2) | (ptr[1] >> 6)) & 0x1F]);
			ret.push_back(encode32[(ptr[1] >> 1) & 0x1F]);
			ret.push_back(encode32[((ptr[1] << 4) | (ptr[2] >> 4)) & 0x1F]);
			ret.push_back(encode32[(ptr[2] << 1) & 0x1F]);
			ret.push_back(space32);
			ret.push_back(space32);
			break;
		case 3:
			ret.push_back(encode32[ptr[0] >> 3]);
			ret.push_back(encode32[((ptr[0] << 2) | (ptr[1] >> 6)) & 0x1F]);
			ret.push_back(encode32[(ptr[1] >> 1) & 0x1F]);
			ret.push_back(encode32[(ptr[1] << 4) & 0x1F]);
			ret.push_back(space32);
			ret.push_back(space32);
			ret.push_back(space32);
			break;
		case 4:
			ret.push_back(encode32[ptr[0] >> 3]);
			ret.push_back(encode32[(ptr[0] << 2) & 0x1F]);
			ret.push_back(space32);
			ret.push_back(space32);
			ret.push_back(space32);
			ret.push_back(space32);
			break;
	}
}

void provider::base32_rev(std::string& ret, const char* buf, size_t size)
{
	static const byte decode32[] = {
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 25,26,27,28,29,30,31,0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,11,12,13,0,
		14,15,16,17,18,19,20,21,22,23,24,0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	};
	constexpr char space32 = '0';

	const char *ptr_end = buf + size - 8;
	for (; buf < ptr_end; buf += 8)
	{
		ret.push_back((decode32[buf[0]] << 3) | (decode32[buf[1]] >> 2));
		ret.push_back((decode32[buf[1]] << 6) | (decode32[buf[2]] << 1) | (decode32[buf[3]] >> 4));
		ret.push_back((decode32[buf[3]] << 4) | (decode32[buf[4]] >> 1));
		ret.push_back((decode32[buf[4]] << 7) | (decode32[buf[5]] << 2) | (decode32[buf[6]] >> 3));
		ret.push_back((decode32[buf[6]] << 5) | decode32[buf[7]]);
	}

	if (buf - ptr_end == 0)
	{
		if (buf[7] == space32)
		{
			ret.push_back((decode32[buf[0]] << 3) | (decode32[buf[1]] >> 2));
			ret.push_back((decode32[buf[1]] << 6) | (decode32[buf[2]] << 1) | (decode32[buf[3]] >> 4));
			ret.push_back((decode32[buf[3]] << 4) | (decode32[buf[4]] >> 1));
			ret.push_back((decode32[buf[4]] << 7) | (decode32[buf[5]] << 2) | (decode32[buf[6]] >> 3));
		}
		else
		{
			ret.push_back((decode32[buf[0]] << 3) | (decode32[buf[1]] >> 2));
			ret.push_back((decode32[buf[1]] << 6) | (decode32[buf[2]] << 1) | (decode32[buf[3]] >> 4));
			ret.push_back((decode32[buf[3]] << 4) | (decode32[buf[4]] >> 1));
			ret.push_back((decode32[buf[4]] << 7) | (decode32[buf[5]] << 2) | (decode32[buf[6]] >> 3));
			ret.push_back((decode32[buf[6]] << 5) | decode32[buf[7]]);
		}
	}
	else if (buf - ptr_end == 1)
	{
		if (buf[4] == space32)
		{
			ret.push_back((decode32[buf[0]] << 3) | (decode32[buf[1]] >> 2));
			ret.push_back((decode32[buf[1]] << 6) | (decode32[buf[2]] << 1) | (decode32[buf[3]] >> 4));
		}
		else
		{
			ret.push_back((decode32[buf[0]] << 3) | (decode32[buf[1]] >> 2));
			ret.push_back((decode32[buf[1]] << 6) | (decode32[buf[2]] << 1) | (decode32[buf[3]] >> 4));
			ret.push_back((decode32[buf[3]] << 4) | (decode32[buf[4]] >> 1));
		}
	}
	else
	{
		ret.push_back((decode32[buf[0]] << 3) | (decode32[buf[1]] >> 2));
	}
}

void provider::hash_short(const std::string& src, std::string& dst)
{
	CryptoPP::SHA1 hasher;
	byte result[hash_short_size];
	memset(result, 0, sizeof(result));
	hasher.CalculateDigest(result, reinterpret_cast<const byte*>(src.data()), src.size());
	base32(dst, result, hash_short_size);
}
