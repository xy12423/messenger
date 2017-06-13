#include "stdafx.h"
#include "global.h"
#include "crypto.h"
#include "session.h"
#include "plugin.h"

template <typename... _Ty>
inline void hash_short(_Ty&&... arg)
{
	crypto::provider::hash_short(std::forward<_Ty>(arg)...);
}

template <typename... _Ty>
inline void base32(_Ty&&... arg)
{
	crypto::provider::base32(std::forward<_Ty>(arg)...);
}

template <typename... _Ty>
inline void base32_rev(_Ty&&... arg)
{
	crypto::provider::base32_rev(std::forward<_Ty>(arg)...);
}

class counting_streambuf :public std::streambuf
{
public:
	counting_streambuf(std::fstream& _stream) :stream(_stream) {}

	int_type overflow(int_type c)
	{
		count++;
		stream.put(static_cast<char>(c));
		return c;
	}

	int sync()
	{
		stream.flush();
		return 0;
	}

	void set_count(size_t _count) { count = _count; }
	size_t get_count() const { return count; }
private:
	std::fstream &stream;
	size_t count = 0;
};

struct data_view
{
	data_view(const char* _data, size_t _size)
		:data(_data), size(_size)
	{}
	data_view(const std::string &_data)
		:data(_data.data()), size(_data.size())
	{}

	template <typename _Ty>
	void read(_Ty& ret);
	inline void read(char& ret) { if (size < 1) throw(plugin_error()); ret = *data; data += 1; size -= 1; }
	inline void read(char* dst, size_t _size) { if (size < _size) throw(plugin_error()); memcpy(dst, data, _size); data += _size; size -= _size; }
	inline void read(std::string& dst, size_t _size) { if (size < _size) throw(plugin_error()); dst.append(data, _size); data += _size; size -= _size; }
	inline void check(size_t count) { if (size < count) throw(plugin_error()); }
	inline void skip(size_t count) { if (size < count) throw(plugin_error()); data += count; size -= count; }

	const char* data;
	size_t size;
};

template <typename _Ty>
void data_view::read(_Ty &ret)
{
	if (size < sizeof(_Ty))
		throw(plugin_error());
	size -= sizeof(_Ty);

	const char *data_end = data + sizeof(_Ty);
	ret = 0;
	for (int i = 0; data < data_end; data++, i += 8)
		ret |= static_cast<uint64_t>(static_cast<uint8_t>(*data)) << i;
}

msg_logger::msg_logger(plugin_interface& _inter)
	:msg_server_plugin(_inter),
	log_stream(new counting_streambuf(log_fstream))
{
}

void msg_logger::init(const config_table_tp& config_items)
{
	if (!load_config(config_items))
		return;
	fs::path imgPath, logPath;
	imgPath = log_path / img_path_name;
	if (!fs::exists(imgPath))
		fs::create_directory(imgPath);
	else if (!fs::is_directory(imgPath))
	{
		enabled = false;
		return;
	}

	logPath = log_path / log_file_name;
	log_fstream.open(logPath.string(), std::ios_base::in | std::ios_base::out | std::ios_base::app | std::ios_base::binary);
	enabled = log_fstream.is_open() && log_fstream;
	if (enabled)
		static_cast<counting_streambuf*>(log_stream.rdbuf())->set_count(static_cast<size_t>(fs::file_size(logPath)));
}

bool msg_logger::load_config(const config_table_tp& config_items)
{
	try
	{
		fs::path _log_path = config_items.at("msg_log_path");
		if (!fs::exists(_log_path))
			fs::create_directories(_log_path);
		else if (!fs::is_directory(_log_path))
			throw(plugin_error());
		log_path = std::move(_log_path);
		std::cout << "Using message log, log path:" << log_path << std::endl;

		try
		{
			std::string offline_msg_lvl_str = config_items.at("offline_msg");
			if (offline_msg_lvl_str == "off")
				offline_msg_lvl = OFF;
			else
			{
				if (offline_msg_lvl_str == "noimg")
					offline_msg_lvl = NOIMG;
				else
					offline_msg_lvl = ON;
				read_data();
				std::cout << "Offline message enabled" << std::endl;
			}
		}
		catch (std::out_of_range &) {}
	}
	catch (plugin_error &) { return false; }
	catch (std::out_of_range &) { return false; }
	return true;
}

void msg_logger::read_data()
{
	fs::path data_path = log_path / data_file_name;
	if (!fs::exists(data_path))
		return;
	std::ifstream fin(data_path.string());

	std::string line;
	record_list::iterator selected;
	std::getline(fin, line);
	while (!fin.eof())
	{
		trim(line);
		if (!line.empty() && line.front() != '#')
		{
			if (line.front() == '[' && line.back() == ']')
			{
				selected = records.emplace(line.substr(1, line.size() - 2), record_tp()).first;
			}
			else
			{
				size_t pos = line.find('=');
				std::string name = line.substr(0, pos), val = line.substr(pos + 1);
				rtrim(name);
				ltrim(val);
				if (name == "byte_count")
					selected->second = std::stol(val);
			}
		}
		std::getline(fin, line);
	}
}

void msg_logger::write_data()
{
	fs::path data_path = log_path / data_file_name;
	std::ofstream fout(data_path.string());
	for (const std::pair<std::string, record_tp> &pair : records)
	{
		fout << '[' << pair.first << ']' << std::endl;
		fout << "byte_count=" << pair.second << std::endl;
	}
}

void msg_logger::on_new_user(const std::string& name)
{
	if (offline_msg_lvl > OFF)
	{
		try
		{
			user_id_type id;
			if (!inter.get_id_by_name(name, id))
				return;
			bool feature_message_from = ((inter.get_feature(id) & flag_message_from) != 0);
			std::string empty_string;

			std::streampos begin = records.at(name);
			log_fstream.seekg(begin);
			std::string stamp, content;
			std::getline(log_fstream, stamp);
			while (!log_fstream.eof())
			{
				std::getline(log_fstream, content);
				switch (content.front())
				{
					case '!':
						if (offline_msg_lvl > NOIMG)
						{
							content.pop_back();
							std::string img_path = (log_path / content.substr(4)).string();
							if (feature_message_from)
							{
								inter.send_image(id, img_path, stamp);
							}
							else
							{
								inter.send_msg(id, stamp, empty_string);
								inter.send_image(id, img_path, empty_string);
							}
						}
						break;
					case ' ':
						if (feature_message_from)
						{
							inter.send_msg(id, content.substr(1), stamp);
						}
						else
						{
							inter.send_msg(id, stamp, empty_string);
							inter.send_msg(id, content.substr(1), empty_string);
						}
						break;
				}
				std::getline(log_fstream, stamp);
			}
			log_fstream.clear();
		}
		catch (std::out_of_range &) {}
		records[name] = static_cast<counting_streambuf*>(log_stream.rdbuf())->get_count();
		write_data();
	}
}

void msg_logger::on_del_user(const std::string& name)
{
	if (offline_msg_lvl > OFF)
	{
		records[name] = static_cast<counting_streambuf*>(log_stream.rdbuf())->get_count();
		write_data();
	}
}

void msg_logger::on_msg(const std::string& name, const std::string& msg)
{
	if (enabled)
	{
		std::time_t cur_time = std::time(nullptr);
		std::string cur_time_str = std::ctime(&cur_time);
		cur_time_str.pop_back();
		log_stream << cur_time_str << ' ' << name << "\n " << msg << std::endl;
	}
}

void msg_logger::on_img(const std::string& name, const char *data, size_t data_size)
{
	if (enabled)
	{
		std::string img_name;
		hash_short(data, img_name);
		fs::path img_rela_path = img_path_name;
		img_rela_path /= img_name;
		std::string img_path = (log_path / img_rela_path).string();
		std::ofstream fout(img_path, std::ios_base::out | std::ios_base::binary);
		fout.write(data, data_size);
		fout.close();

		std::time_t cur_time = std::time(nullptr);
		std::string cur_time_str = std::ctime(&cur_time);
		cur_time_str.pop_back();
		log_stream << cur_time_str << ' ' << name << '\n' << "![](" << img_rela_path.string() << ')' << std::endl;
	}
}

void server_mail::init(const config_table_tp& config_items)
{
	if (!load_config(config_items))
		return;
	enabled = true;
}

bool server_mail::load_config(const config_table_tp& config_items)
{
	try
	{
		fs::path _mail_path = config_items.at("mail_path");
		if (!fs::exists(_mail_path))
			fs::create_directories(_mail_path);
		else if (!fs::is_directory(_mail_path))
			throw(plugin_error());
		mails_path = std::move(_mail_path);
		std::cout << "Mail enabled, mail path:" << mails_path << std::endl;
	}
	catch (plugin_error &) { return false; }
	catch (std::out_of_range &) { return false; }
	return true;
}

void server_mail::on_new_user(const std::string& name)
{
	if (!enabled)
		return;
	fs::path mail_path = mails_path / (name + ".dat");
	if (fs::exists(mail_path))
	{
		user_id_type id;
		inter.get_id_by_name(name, id);

		std::ifstream fin(mail_path.string());
		std::string line;
		std::getline(fin, line);
		while (!fin.eof())
		{
			inter.send_msg(id, line);
			std::getline(fin, line);
		}
		fin.close();

		fs::remove(mail_path);
	}
}

void server_mail::on_cmd(const std::string& name, user_type type, const std::string& cmd, const std::string& arg)
{
	if (!enabled)
		return;
	if (cmd == "mail")
	{
		size_t pos = arg.find(' ');
		std::string target_name = arg.substr(0, pos), content = arg.substr(pos + 1);

		user_id_type id;
		if (inter.get_id_by_name(target_name, id))
		{
			inter.send_msg(id, "From:" + name + '\n' + content);
		}
		else
		{
			fs::path mail_path = mails_path / (target_name + ".dat");
			std::ofstream fout(mail_path.string(), std::ios_base::out | std::ios_base::app);

			std::time_t cur_time = std::time(nullptr);
			std::string cur_time_str = std::ctime(&cur_time);
			cur_time_str.pop_back();
			fout << "Time:" << cur_time_str << std::endl << "From:" << name << std::endl << content << std::endl;

			fout.close();
		}
	}
}

void file_storage::init(const config_table_tp& config_items)
{
	if (!load_config(config_items))
		return;
	enabled = true;
}

bool file_storage::load_config(const config_table_tp& config_items)
{
	try
	{
		fs::path _files_path = config_items.at("files_path");
		if (!fs::exists(_files_path))
			fs::create_directories(_files_path);
		else if (!fs::is_directory(_files_path))
			throw(plugin_error());
		files_path = std::move(_files_path);

		load_data();

		iosrv_work = std::make_shared<asio::io_service::work>(iosrv);
		std::thread thread([this]() {
			while (iosrv_work)
			{
				try
				{
					iosrv.run();
				}
				catch (...) {}
			}
			stopped = true;
		});
		thread.detach();

		std::cout << "File logger enabled, save path:" << files_path << std::endl;
	}
	catch (plugin_error &) { return false; }
	catch (std::out_of_range &) { return false; }
	return true;
}

void file_storage::load_data()
{
	fs::path data_path = files_path / data_file_name;
	if (!fs::exists(data_path))
		return;
	std::ifstream fin(data_path.string());

	std::string line;
	hashmap_tp::iterator selected;
	const file_info empty_file_info;
	std::getline(fin, line);
	while (!fin.eof())
	{
		trim(line);
		if (!line.empty() && line.front() != '#')
		{
			if (line.front() == '[' && line.back() == ']')
			{
				selected = hash_map.emplace(line.substr(1, line.size() - 2), empty_file_info).first;
			}
			else
			{
				size_t pos = line.find('=');
				std::string name = line.substr(0, pos), val = line.substr(pos + 1);
				rtrim(name);
				ltrim(val);
				if (name == "file_name")
					selected->second.file_name = val;
				else if (name == "upload_user")
					selected->second.upload_user = val;
			}
		}
		std::getline(fin, line);
	}
}

void file_storage::save_data()
{
	fs::path data_path = files_path / data_file_name;
	std::ofstream fout(data_path.string());
	for (const hashmap_tp::value_type &pair : hash_map)
	{
		fout << '[' << pair.first << ']' << std::endl;
		fout << "file_name=" << pair.second.file_name << std::endl;
		fout << "upload_user=" << pair.second.upload_user << std::endl;
	}
}

void file_storage::on_del_user(const std::string& name)
{
	try
	{
		recv_tasks.erase(name);
	}
	catch (...) {}
	try
	{
		user_id_type id;
		inter.get_id_by_name(name, id);
		send_tasks.erase(id);
	}
	catch (...) {}
}

void file_storage::on_cmd(const std::string& name, user_type type, const std::string& cmd, const std::string& arg)
{
	if (!enabled)
		return;
	if (cmd == "file_get")
	{
		user_id_type id;
		if (inter.get_id_by_name(name, id))
			start(id, arg);
	}
	else if (cmd == "file_list")
	{
		user_id_type id;
		if (!inter.get_id_by_name(name, id))
			return;
		std::string msg;

		for (const hashmap_tp::value_type &pair : hash_map)
		{
			msg.append(pair.first);
			msg.append(":\n");
			msg.append(pair.second.file_name);
			msg.push_back('\n');
		}
		msg.pop_back();

		inter.send_msg(id, msg);
	}
	else if (cmd == "file_del")
	{
		user_id_type id;
		if (!inter.get_id_by_name(name, id))
			return;
		hashmap_tp::iterator selected = hash_map.find(arg);
		if (selected == hash_map.end())
		{
			inter.send_msg(id, "File not found");
		}
		else if (type >= ADMIN || (type == USER && selected->second.upload_user == name))
		{
			boost::system::error_code ec;
			fs::remove(files_path / selected->first, ec);
			if (ec)
			{
				inter.send_msg(id, "Failed to delete");
			}
			else
			{
				hash_map.erase(selected);
				save_data();
				inter.send_msg(id, "File deleted");
			}
		}
		else
		{
			inter.send_msg(id, "Insufficient privilege");
		}
	}
}

void file_storage::on_file_h(const std::string& name, const char *_data, size_t data_size)
{
	if (!enabled)
		return;

	recv_tasks_tp::iterator itr = recv_tasks.find(name);
	if (itr != recv_tasks.end())
		recv_tasks.erase(itr);

	data_view data(_data, data_size);
	data_size_type block_count_all, file_name_len;

	try
	{
		recv_task &task = recv_tasks.emplace(name, recv_task(files_path / ("user_" + name))).first->second;

		data.read(block_count_all);
		data.read(file_name_len);

		data.read(task.info.file_name, file_name_len);
		task.info.upload_user = name;
		
		std::string &file_name = task.info.file_name;
		size_t pos = file_name.rfind('/');
		if (pos != std::string::npos)
			file_name.erase(0, pos + 1);
		pos = file_name.rfind('\\');
		if (pos != std::string::npos)
			file_name.erase(0, pos + 1);

		task.block_count_all = block_count_all;
	}
	catch (plugin_error &)
	{
		recv_tasks_tp::iterator itr = recv_tasks.find(name);
		if (itr != recv_tasks.end())
			recv_tasks.erase(itr);
	}
}

void file_storage::on_file_b(const std::string& name, const char *_data, size_t data_size)
{
	if (!enabled)
		return;
	recv_tasks_tp::iterator selected = recv_tasks.find(name);
	if (selected == recv_tasks.end())
		return;
	recv_task &task = selected->second;

	data_view data(_data, data_size);
	data_size_type dataSize;

	try
	{
		data.read(dataSize);
		data.check(dataSize);

		task.fout.write(data.data, dataSize);
		task.hasher.Update(reinterpret_cast<const byte*>(data.data), dataSize);

		data.skip(dataSize);
		task.block_count++;

		if (task.block_count > task.block_count_all)
		{
			task.fout.close();

			byte sha1[hash_short_size];
			task.hasher.Final(sha1);
			std::string base32_val;
			base32(base32_val, sha1, hash_short_size);
			fs::rename(files_path / ("user_" + name), files_path / base32_val);
			hash_map.emplace(base32_val, task.info);

			recv_tasks.erase(selected);
			save_data();
		}
	}
	catch (plugin_error &)
	{
		recv_tasks.erase(selected);
	}
}

void file_storage::on_plugin_data(const std::string& name, const char *_data, size_t data_size)
{
	if (!enabled)
		return;
	if (data_size < 1 || *_data != pak_file_storage)
		return;
	data_view data(_data + 1, data_size - 1);

	try
	{
		char type;
		data.read(type);
		switch (type)
		{
			case OP_LIST:
			{
				user_id_type id;
				if (!inter.get_id_by_name(name, id))
					break;
				std::string list;
				list.push_back(PAC_TYPE_PLUGIN_DATA);
				list.push_back(pak_file_storage);
				list.push_back(static_cast<char>(hash_map.size() & 0xFF));
				list.push_back(static_cast<char>(hash_map.size() >> 8));
				list.push_back(static_cast<char>(hash_map.size() >> 16));
				list.push_back(static_cast<char>(hash_map.size() >> 24));

				std::string key;
				for (const hashmap_tp::value_type &pair : hash_map)
				{
					key.clear();
					const std::string &file_name = pair.second.file_name;
					base32_rev(key, pair.first.data(), pair.first.size());
					list.push_back(static_cast<char>(key.size() & 0xFF));
					list.push_back(static_cast<char>(key.size() >> 8));
					list.push_back(static_cast<char>(key.size() >> 16));
					list.push_back(static_cast<char>(key.size() >> 24));
					list.append(key);
					list.push_back(static_cast<char>(file_name.size() & 0xFF));
					list.push_back(static_cast<char>(file_name.size() >> 8));
					list.push_back(static_cast<char>(file_name.size() >> 16));
					list.push_back(static_cast<char>(file_name.size() >> 24));
					list.append(file_name);
				}

				inter.send_data(id, std::move(list), msgr_proto::session_base::priority_plugin);
				break;
			}
			case OP_GET:
			{
				user_id_type id;
				if (!inter.get_id_by_name(name, id))
					break;
				std::string key;
				base32(key, reinterpret_cast<const byte*>(data.data), data.size);
				start(id, key);
				break;
			}
			case OP_CONTINUE:
			{
				user_id_type id;
				if (!inter.get_id_by_name(name, id))
					break;

				uint32_t key_size, skip_size;
				std::string key, key_bin;
				data.read(key_size);
				data.read(key_bin, key_size);
				data.read(skip_size);

				base32(key, reinterpret_cast<const byte*>(key_bin.data()), key_size);
				start(id, key, skip_size);
				break;
			}
			case OP_DEL:
			{
				user_id_type id;
				if (!inter.get_id_by_name(name, id))
					break;

				std::string key;
				base32(key, reinterpret_cast<const byte*>(data.data), data.size);

				hashmap_tp::iterator selected = hash_map.find(key);
				if (selected == hash_map.end())
				{
					inter.send_msg(id, "File not found");
				}
				else if (type >= ADMIN || (type == USER && selected->second.upload_user == name))
				{
					boost::system::error_code ec;
					fs::remove(files_path / selected->first, ec);
					if (ec)
					{
						inter.send_msg(id, "Failed to delete");
					}
					else
					{
						hash_map.erase(selected);
						save_data();
						inter.send_msg(id, "File deleted");
					}
				}
				else
				{
					inter.send_msg(id, "Insufficient privilege");
				}
			}
		}
	}
	catch (plugin_error &) {}
}

void file_storage::start(user_id_type uID, const std::string& hash, size_t begin)
{
	iosrv.post([this, uID, hash, begin]() {
		if (send_tasks.count(uID) > 0)
		{
			inter.send_msg(uID, "Already sending a file");
			return;
		}
		fs::path path = files_path / hash;
		hashmap_tp::iterator selected = hash_map.find(hash);
		if (!fs::exists(path) || selected == hash_map.end())
		{
			inter.send_msg(uID, "File not found");
			return;
		}
		send_task &new_task = send_tasks.emplace(uID, send_task(uID, selected->second.file_name, path)).first->second;

		try
		{
			if (new_task.fin.is_open())
			{
				uintmax_t file_size = fs::file_size(path);
				new_task.fin.seekg(begin);
				if (!new_task.fin.good() || file_size <= begin)
				{
					inter.send_msg(uID, "Invalid filestream");
					send_tasks.erase(uID);
					return;
				}

				data_size_type blockCountAll = static_cast<data_size_type>(file_size - begin);
				if (blockCountAll % file_block_size == 0)
					blockCountAll /= file_block_size;
				else
					blockCountAll = blockCountAll / file_block_size + 1;
				if (blockCountAll < 1)
				{
					inter.send_msg(uID, "Empty file");
					send_tasks.erase(uID);
					return;
				}
				new_task.block_count_all = blockCountAll;

				write(uID);
			}
			else
			{
				send_tasks.erase(uID);
				return;
			}
		}
		catch (...)
		{
			send_tasks.erase(uID);
		}
	});
}

void file_storage::send_header(send_task &task)
{;
	data_size_type block_count_all = task.block_count_all;
	data_size_type name_size = static_cast<data_size_type>(task.file_name.size());

	std::string head(1, PAC_TYPE_FILE_H);
	head.reserve(1 + sizeof(data_size_type) + sizeof(data_size_type) + name_size);
	for (int i = 1; i <= sizeof(data_size_type); i++)
	{
		head.push_back(static_cast<char>(block_count_all & 0xFF));
		block_count_all >>= 8;
	}
	for (int i = 1; i <= sizeof(data_size_type); i++)
	{
		head.push_back(static_cast<char>(name_size & 0xFF));
		name_size >>= 8;
	}
	head.append(task.file_name);

	inter.send_data(task.uID, std::move(head), msgr_proto::session_base::priority_file);
}

void file_storage::stop(user_id_type uID)
{
	iosrv.post([this, uID]() {
		send_tasks.erase(uID);
	});
}

void file_storage::write(user_id_type uID)
{
	std::string send_buf;

	send_task &task = send_tasks.at(uID);
	if (task.block_count == 1)
		send_header(task);
	if (task.block_count > task.block_count_all)
	{
		send_tasks.erase(uID);
		return;
	}

	task.fin.read(task.buffer.get(), file_block_size);
	std::streamsize size_read = task.fin.gcount();
	data_size_type size = static_cast<data_size_type>(size_read);

	send_buf.reserve(1 + sizeof(data_size_type) + size);
	send_buf.push_back(PAC_TYPE_FILE_B);
	for (int i = 1; i <= sizeof(data_size_type); i++)
	{
		send_buf.push_back(static_cast<char>(size & 0xFF));
		size >>= 8;
	}
	send_buf.append(task.buffer.get(), static_cast<size_t>(size_read));

	inter.send_data(task.uID, std::move(send_buf), msgr_proto::session_base::priority_file, [this, uID]() {
		iosrv.post([this, uID]() {
			if (send_tasks.count(uID) > 0)
			{
				try
				{
					write(uID);
				}
				catch (...)
				{
					send_tasks.erase(uID);
				}
			}
		});
	});
	task.block_count++;

	if (!task.fin.good())
		send_tasks.erase(uID);
}

void key_storage::init(const config_table_tp& config_items)
{
	try
	{
		keys_path = config_items.at("keys_path");
		if (!fs::exists(keys_path))
			fs::create_directories(keys_path);
		else if (!fs::is_directory(keys_path))
			throw(plugin_error());
		load_data();
		std::cout << "Key storage enabled, path:" << keys_path << std::endl;
		storage_enabled = true;
	}
	catch (plugin_error &) { storage_enabled = false; }
	catch (std::out_of_range &) { storage_enabled = false; }
	try
	{
		const std::string &mode = config_items.at("mode");
		if (mode == "strict" && storage_enabled)
		{
			auth_enabled = true;
			std::cout << "Key auth enabled" << std::endl;
		}
	}
	catch (plugin_error &) { auth_enabled = false; }
	catch (std::out_of_range &) { auth_enabled = false; }
}

void key_storage::load_data()
{
	std::vector<char> key_buf, ex_buf;
	char size_buf[sizeof(uint16_t)];
	for (fs::directory_iterator p(keys_path), pEnd; p != pEnd; p++)
	{
		std::ifstream fin(p->path().string(), std::ios_base::in | std::ios_base::binary);
		std::string user = p->path().stem().string();
		
		fin.read(size_buf, sizeof(uint16_t));
		while (!fin.eof())
		{
			//read key
			key_buf.resize(static_cast<uint16_t>(size_buf[0]) | (size_buf[1] << 8));
			fin.read(key_buf.data(), key_buf.size());
			if (fin.eof())
				throw(plugin_error());
			//read ex
			fin.read(size_buf, sizeof(uint16_t));
			ex_buf.resize(static_cast<uint16_t>(size_buf[0]) | (size_buf[1] << 8));
			fin.read(ex_buf.data(), ex_buf.size());
			if (fin.gcount() != ex_buf.size())
				throw(plugin_error());
			//emplace
			keys.emplace(user, key_item(std::string(key_buf.data(), key_buf.size()), std::string(ex_buf.data(), ex_buf.size())));
			//read next size
			fin.read(size_buf, sizeof(uint16_t));
		}
	}
}

void key_storage::load_data(const std::string& user, data_view& data)
{
	std::vector<char> key_buf, ex_buf;
	char size_buf[sizeof(uint16_t)];
	std::unordered_map<std::string, std::string> keys_loaded;

	while (data.size != 0)
	{
		data.read(size_buf, sizeof(uint16_t));
		//read key
		key_buf.resize(static_cast<uint16_t>(size_buf[0]) | (size_buf[1] << 8));
		data.read(key_buf.data(), key_buf.size());
		//read ex
		data.read(size_buf, sizeof(uint16_t));
		ex_buf.resize(static_cast<uint16_t>(size_buf[0]) | (size_buf[1] << 8));
		data.read(ex_buf.data(), ex_buf.size());
		//emplace to temp
		keys_loaded.emplace(std::string(key_buf.data(), key_buf.size()), std::string(ex_buf.data(), ex_buf.size()));
	}

	std::pair<key_list_tp::const_iterator, key_list_tp::const_iterator> itrs = keys.equal_range(user);
	key_list_tp::const_iterator &itr = itrs.first, &itr_end = itrs.second;
	auto itr_load_end = keys_loaded.end();
	for (; itr != itr_end; itr++)
	{
		auto itr_load = keys_loaded.find(itr->second.key);
		if (itr_load != itr_load_end)
			keys_loaded.erase(itr_load);
	}

	auto itr_load = keys_loaded.begin();
	for (; itr_load != itr_load_end; itr_load++)
		keys.emplace(user, key_item(itr_load->first, std::move(itr_load->second)));
}

void key_storage::save_data(const std::string& user)
{
	std::ofstream fout((keys_path / user).string(), std::ios_base::out | std::ios_base::binary);
	std::pair<key_list_tp::const_iterator, key_list_tp::const_iterator> itrs = keys.equal_range(user);
	key_list_tp::const_iterator &itr = itrs.first, &itr_end = itrs.second;
	for (; itr != itr_end; itr++)
	{
		const std::string &key = itr->second.key, &ex = itr->second.ex;
		fout.put(static_cast<char>(key.size() & 0xFF));
		fout.put(static_cast<char>(key.size() >> 8));
		fout.write(key.data(), key.size());
		fout.put(static_cast<char>(ex.size() & 0xFF));
		fout.put(static_cast<char>(ex.size() >> 8));
		fout.write(ex.data(), ex.size());
	}
}

bool key_storage::on_join(const std::string& user, const std::string& key)
{
	if (!auth_enabled)
		return true;
	std::pair<key_list_tp::const_iterator, key_list_tp::const_iterator> itrs = keys.equal_range(user);
	key_list_tp::const_iterator &itr = itrs.first, &itr_end = itrs.second;
	for (; itr != itr_end; itr++)
		if (itr->second.key == key)
			return true;
	return false;
}

void key_storage::on_file_h(const std::string& user, const char *_data, size_t data_size)
{
	data_view data(_data, data_size);
	data_size_type block_count_all, file_name_len;

	recv_tasks_tp::iterator itr = recv_tasks.find(user);
	if (itr != recv_tasks.end())
		recv_tasks.erase(itr);

	try
	{
		recv_task &task = recv_tasks.emplace(user, recv_task()).first->second;

		data.read(block_count_all);
		data.read(file_name_len);
		data.skip(file_name_len);

		task.block_count_all = block_count_all;
	}
	catch (plugin_error &)
	{
		recv_tasks_tp::iterator itr = recv_tasks.find(user);
		if (itr != recv_tasks.end())
			recv_tasks.erase(itr);
	}
}

int key_storage::on_file_b(const std::string& user, const char *_data, size_t data_size)
{
	recv_tasks_tp::iterator selected = recv_tasks.find(user);
	if (selected == recv_tasks.end())
		return 1;
	recv_task &task = selected->second;

	data_view data(_data, data_size);
	data_size_type dataSize;

	try
	{
		data.read(dataSize);
		data.check(dataSize);

		data.read(task.buf, dataSize);
		task.block_count++;

		if (task.block_count > task.block_count_all)
		{
			if (storage_enabled)
			{
				data_view data(task.buf);
				load_data(user, data);
				save_data(user);
				recv_tasks.erase(selected);
			}
			return -1;
		}
	}
	catch (plugin_error &)
	{
		recv_tasks.erase(selected);
		return 1;
	}
	return 0;
}
