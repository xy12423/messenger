#include "stdafx.h"
#include "global.h"
#include "crypto.h"
#include "session.h"
#include "plugin.h"

class counting_streambuf :public std::streambuf
{
public:
	counting_streambuf(std::fstream &_stream) :stream(_stream) {}

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

msg_logger::msg_logger(plugin_interface &_inter)
	:msg_server_plugin(_inter),
	log_stream(new counting_streambuf(log_fstream))
{
}

void msg_logger::init(const config_table_tp &config_items)
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

bool msg_logger::load_config(const config_table_tp &config_items)
{
	try
	{
		fs::path _log_path = config_items.at("msg_log_path");
		if (!fs::exists(_log_path))
			fs::create_directories(_log_path);
		else if (!fs::is_directory(_log_path))
			throw(0);
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
	catch (int) { return false; }
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
					selected->second = std::stoi(val);
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

void msg_logger::on_new_user(const std::string &name)
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

void msg_logger::on_del_user(const std::string &name)
{
	if (offline_msg_lvl > OFF)
	{
		records[name] = static_cast<counting_streambuf*>(log_stream.rdbuf())->get_count();
		write_data();
	}
}

void msg_logger::on_msg(const std::string &name, const std::string &msg)
{
	if (enabled)
	{
		std::time_t cur_time = std::time(nullptr);
		std::string cur_time_str = std::ctime(&cur_time);
		cur_time_str.pop_back();
		log_stream << cur_time_str << ' ' << name << "\n " << msg << std::endl;
	}
}

void msg_logger::on_img(const std::string &name, const char *data, size_t data_size)
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
