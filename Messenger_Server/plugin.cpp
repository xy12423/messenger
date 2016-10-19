#include "stdafx.h"
#include "global.h"
#include "crypto.h"
#include "session.h"
#include "plugin.h"

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
	inline void read(_Ty &ret) {
		if (size < sizeof(_Ty))
			throw(plugin_error());
		size -= sizeof(_Ty);
		ret = boost::endian::little_to_native(*reinterpret_cast<const _Ty*>(data));
		data += sizeof(_Ty);
	}
	inline void read(char* dst, size_t _size) { if (size < _size) throw(plugin_error()); memcpy(dst, data, _size); data += _size; size -= _size; }
	inline void read(std::string& dst, size_t _size) { if (size < _size) throw(plugin_error()); dst.append(data, _size); data += _size; size -= _size; }
	inline void check(size_t count) { if (size < count) throw(plugin_error()); }
	inline void skip(size_t count) { if (size < count) throw(plugin_error()); data += count; size -= count; }

	const char* data;
	size_t size;
};

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
			inter.get_id_by_name(name, id);
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
							inter.send_msg(id, stamp);
							inter.send_image(id, img_path);
						}
						break;
					case ' ':
						inter.send_msg(id, stamp);
						inter.send_msg(id, content.substr(1));
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

void server_mail::on_cmd(const std::string& name, const std::string& cmd, const std::string& arg)
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

void file_storage::init(const config_table_tp& config_items)
{
	if (!load_config(config_items))
		return;
	enabled = true;
}

void file_storage::on_cmd(const std::string& name, const std::string& cmd, const std::string& arg)
{
	if (!enabled)
		return;
	if (cmd == "file")
	{
		user_id_type id;
		inter.get_id_by_name(name, id);
		start(id, arg);
	}
	else if (cmd == "list_file")
	{
		user_id_type id;
		inter.get_id_by_name(name, id);
		std::string msg;

		for (const hashmap_tp::value_type &pair : hash_map)
		{
			msg.append(pair.first);
			msg.append(":\n");
			msg.append(pair.second);
			msg.push_back('\n');
		}
		msg.pop_back();

		inter.send_msg(id, msg);
	}
}

void file_storage::on_file_h(const std::string& name, const char *_data, size_t data_size)
{
	if (!enabled)
		return;
	data_view data(_data, data_size);
	data_size_type block_count_all, file_name_len;
	
	try
	{
		recv_task &task = recv_tasks.emplace(name, recv_task(files_path / ("user_" + name))).first->second;

		data.read(block_count_all);
		data.read(file_name_len);

		data.read(task.file_name, file_name_len);

		task.block_count_all = block_count_all;
	}
	catch (plugin_error &) {}
}

void file_storage::on_file_b(const std::string& name, const char *_data, size_t data_size)
{
	if (!enabled)
		return;
	std::unordered_map<std::string, recv_task>::iterator selected = recv_tasks.find(name);
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
			hash_map.emplace(base32_val, task.file_name);

			recv_tasks.erase(selected);
			save_data();
		}
	}
	catch (plugin_error &) {}
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
			try
			{
				iosrv.run();
			}
			catch (...) {}
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
	const std::string empty_string;
	std::getline(fin, line);
	while (!fin.eof())
	{
		trim(line);
		if (!line.empty() && line.front() != '#')
		{
			if (line.front() == '[' && line.back() == ']')
			{
				selected = hash_map.emplace(line.substr(1, line.size() - 2), empty_string).first;
			}
			else
			{
				size_t pos = line.find('=');
				std::string name = line.substr(0, pos), val = line.substr(pos + 1);
				rtrim(name);
				ltrim(val);
				if (name == "file_name")
					selected->second = val;
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
		fout << "file_name=" << pair.second << std::endl;
	}
}

void file_storage::start(user_id_type uID, const std::string& hash)
{
	iosrv.post([this, uID, hash]() {
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
		send_task &new_task = send_tasks.emplace(uID, send_task(uID, selected->second, path)).first->second;

		try
		{
			if (new_task.fin.is_open())
			{
				data_size_type blockCountAll = static_cast<data_size_type>(fs::file_size(path));
				if (blockCountAll % file_block_size == 0)
					blockCountAll /= file_block_size;
				else
					blockCountAll = blockCountAll / file_block_size + 1;
				if (blockCountAll < 1)
				{
					inter.send_msg(uID, "Empty file");
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
	data_size_type blockCountAll_LE = boost::endian::native_to_little(task.block_count_all);
	std::string head(1, PAC_TYPE_FILE_H);
	head.append(reinterpret_cast<const char*>(&blockCountAll_LE), sizeof(data_size_type));
	std::string name(task.file_name);
	insLen(name);
	head.append(name);

	inter.send_data(task.uID, std::move(head));
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
	send_buf.push_back(PAC_TYPE_FILE_B);
	data_size_type len = boost::endian::native_to_little(static_cast<data_size_type>(size_read));
	send_buf.append(reinterpret_cast<const char*>(&len), sizeof(data_size_type));
	send_buf.append(task.buffer.get(), static_cast<size_t>(size_read));

	inter.send_data(task.uID, std::move(send_buf), [this, uID]() {
		iosrv.post([this, uID]() {
			if (send_tasks.count(uID) > 0)
				write(uID);
		});
	});
	task.block_count++;

	if (task.fin.eof())
		send_tasks.erase(uID);
}
