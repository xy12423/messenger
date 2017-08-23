#include "stdafx.h"

using namespace CryptoPP;

AutoSeededRandomPool prng;
typedef uint32_t key_id_type;
struct key_item
{
	key_item() {};
	template <typename _Ty1, typename _Ty2>
	key_item(_Ty1&& _key, _Ty2&& _ex) :key(std::forward<_Ty1>(_key)), ex(std::forward<_Ty2>(_ex)) {};

	std::string key, ex;
};
std::map<key_id_type, key_item> keys;

bool load_private(const std::string& path)
{
	try
	{
		ECIES<ECP>::Decryptor d0;
		ECIES<ECP>::PrivateKey &privateKey = d0.AccessKey();
		FileSource fs(path.c_str(), true);
		privateKey.Load(fs);
		if (!privateKey.Validate(prng, 3))
			return false;

		std::string ret;
		StringSink buf(ret);
		ECIES<ECP>::Encryptor e0(d0);
		e0.GetPublicKey().Save(buf);

		key_id_type id = static_cast<key_id_type>(keys.size());
		keys.emplace(id, key_item(ret, "my_private"));
		return true;
	}
	catch (...) {}
	return false;
}

bool load_public(const std::string& path)
{
	try
	{
		std::ifstream fin(path, std::ios_base::in | std::ios_base::binary);
		if (!fin || !fin.is_open())
			return false;

		std::vector<char> buf_key, buf_ex;
		char size_buf[sizeof(uint16_t)];
		fin.read(size_buf, sizeof(uint16_t));
		while (!fin.eof())
		{
			//read key
			buf_key.resize(static_cast<uint16_t>(size_buf[0]) | (size_buf[1] << 8));
			fin.read(buf_key.data(), buf_key.size());
			if (fin.eof())
				return false;
			//read extra data
			fin.read(size_buf, sizeof(uint16_t));
			buf_ex.resize(static_cast<uint16_t>(size_buf[0]) | (size_buf[1] << 8));
			fin.read(buf_ex.data(), buf_ex.size());
			if (fin.gcount() != buf_ex.size())
				return false;
			//emplace
			key_id_type id = static_cast<key_id_type>(keys.size());
			keys.emplace(id, key_item(std::string(buf_key.data(), buf_key.size()), std::string(buf_ex.data(), buf_ex.size())));
			//read next size
			fin.read(size_buf, sizeof(uint16_t));
		}

		fin.close();
		return true;
	}
	catch (...) {}
	return false;
}

bool generate_private(const std::string& path)
{
	try
	{
		const OID CURVE = ASN1::secp521r1();

		ECIES<ECP>::Decryptor d0;
		ECIES<ECP>::PrivateKey &privateKey = d0.AccessKey();
		privateKey.GenerateRandom(prng, MakeParameters(Name::GroupOID(), CURVE));
		FileSink fs(path.data(), true);
		privateKey.Save(fs);
		return true;
	}
	catch (...) {}
	return false;
}

bool save_public(const std::string& path)
{
	try
	{
		std::ofstream fout(path, std::ios_base::out | std::ios_base::binary);
		if (!fout || !fout.is_open())
			return false;

		auto itr = keys.begin(), itrEnd = keys.end();
		for (; itr != itrEnd; itr++)
		{
			const key_item &item = itr->second;
			const std::string &key = item.key, &ex = item.ex;
			fout.put(static_cast<char>(key.size()));
			fout.put(static_cast<char>(key.size() >> 8));
			fout.write(key.data(), key.size());
			fout.put(static_cast<char>(ex.size()));
			fout.put(static_cast<char>(ex.size() >> 8));
			fout.write(ex.data(), ex.size());
		}

		fout.close();
	}
	catch (...) {}
	return false;
}

void print_list()
{
	auto itr = keys.begin(), itrEnd = keys.end();
	for (; itr != itrEnd; itr++)
	{
		const key_item &item = itr->second;
		const std::string &key = item.key, &ex = item.ex;
		std::cout << "ID:" << itr->first << std::endl;
		std::cout << "Comment:" << ex << std::endl;
	}
}

void edit()
{
	while (true)
	{
		print_list();
		int id;
		std::cout << "Input the ID of the key to be edited(-1 to quit):" << std::endl;
		std::cin >> id;
		if (id == -1)
			break;
		std::map<key_id_type, key_item>::iterator itr = keys.find(id);
		if (itr == keys.end())
		{
			std::cout << "ID not found" << std::endl;
			continue;
		}

		key_item &key = itr->second;
		std::string item, val;
		std::getline(std::cin, item);
		std::getline(std::cin, item);
		while (!item.empty())
		{
			size_t pos = item.find('=');
			if (pos != std::string::npos)
			{
				val.assign(item, pos + 1);
				item.erase(pos);
			}

			if (item == "comment")
			{
				key.ex = val;
			}
			else if (item == "delete")
			{
				keys.erase(itr);
				break;
			}

			std::getline(std::cin, item);
		}
	}
}

void print_usage()
{

}

int main(int argc, char *argv[])
{
	std::string out, priv, pub;
	int i;
	for (i = 1; i < argc; i++)
	{
		if (strcmp(argv[i], "-o") == 0)
			out = argv[++i];
		else if (strcmp(argv[i], "-k") == 0)
			pub = argv[++i];
		else if (strcmp(argv[i], "-K") == 0)
			priv = argv[++i];
		else
			break;
	}
	if (i >= argc)
	{
		print_usage();
		return EXIT_FAILURE;
	}

	try
	{
		if (!priv.empty())
			if (!load_private(priv))
				throw(std::runtime_error("Failed to load private"));
	}
	catch (std::exception& ex)
	{
		std::cerr << ex.what() << std::endl;
		return EXIT_FAILURE;
	}

	try
	{
		if (!pub.empty())
			if (!load_public(pub))
				throw(std::runtime_error("Failed to load public"));
	}
	catch (std::exception& ex)
	{
		std::cerr << ex.what() << std::endl;
		return EXIT_FAILURE;
	}

	if (strcmp(argv[i], "edit") == 0)
	{
		edit();
		save_public(out);
	}
	else if (strcmp(argv[i], "export") == 0)
	{
		save_public(out);
	}
	else
	{
		print_usage();
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
