#include "stdafx.h"
#include "crypto.h"
#include "session.h"
#include "plugin.h"

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
	log_stream.open(logPath.string(), std::ios_base::out | std::ios_base::app);
	enabled = log_stream.is_open() && log_stream;
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
		return true;
	}
	catch (int) {}
	catch (std::out_of_range &) {}
	return false;
}

void msg_logger::on_msg(const std::string &name, const std::string &msg)
{
	if (enabled)
	{
		std::time_t cur_time = std::time(nullptr);
		std::string cur_time_str = std::ctime(&cur_time);
		cur_time_str.pop_back();
		log_stream << cur_time_str << ' ' << name << '\n' << msg << std::endl;
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
