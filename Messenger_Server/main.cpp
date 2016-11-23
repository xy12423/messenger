#include "stdafx.h"
#include "global.h"
#include "crypto.h"
#include "crypto_man.h"
#include "session.h"
#include "plugin.h"
#include "main.h"

const std::string empty_string;

std::promise<void> exit_promise;
config_table_tp config_items;

asio::io_service main_iosrv, misc_iosrv, cryp_iosrv;
std::unique_ptr<crypto::server> crypto_srv;
std::unique_ptr<cli_server> srv;
cli_plugin_interface i_plugin;
plugin_manager m_plugin(i_plugin);
key_storage user_key_storage;
volatile bool server_on = true;

const char *msg_new_user = "New user:", *msg_del_user = "Leaving user:";
const char *msg_input_name = "Username:", *msg_input_pass = "Password:", *msg_welcome = "Welcome", *msg_unauthed_key = "Key unauthorized";

const char* privatekeyFile = ".privatekey";

bool cli_plugin_interface::get_id_by_name(const std::string& name, user_id_type& id)
{
	return srv->get_id_by_name(name, id);
}

void cli_plugin_interface::broadcast_msg(const std::string& msg)
{
	srv->broadcast_msg(server_uid, msg);
}

void cli_plugin_interface::send_msg(user_id_type id, const std::string& msg)
{
	srv->send_msg(id, msg);
}

void cli_plugin_interface::send_image(user_id_type id, const std::string& path)
{
	const size_t read_buf_size = 0x10000;
	std::string img_buf;
	std::ifstream fin(path, std::ios_base::in | std::ios_base::binary);
	if (!fin || !fin.is_open())
		return;
	std::unique_ptr<char[]> read_buf = std::make_unique<char[]>(read_buf_size);
	while (!fin.eof())
	{
		fin.read(read_buf.get(), read_buf_size);
		img_buf.append(read_buf.get(), static_cast<size_t>(fin.gcount()));
	}
	fin.close();
	insLen(img_buf);
	img_buf.insert(0, 1, PAC_TYPE_IMAGE);
	srv->send_data(id, img_buf, msgr_proto::session::priority_msg);
}

void cli_plugin_interface::send_data(user_id_type id, const std::string& data)
{
	srv->send_data(id, data, msgr_proto::session::priority_file);
}

void cli_plugin_interface::send_data(user_id_type id, const std::string& data, std::function<void()>&& callback)
{
	srv->send_data(id, data, msgr_proto::session::priority_file, std::move(callback));
}

void cli_plugin_interface::send_data(user_id_type id, std::string&& data)
{
	srv->send_data(id, std::move(data), msgr_proto::session::priority_file);
}

void cli_plugin_interface::send_data(user_id_type id, std::string&& data, std::function<void()>&& callback)
{
	srv->send_data(id, std::move(data), msgr_proto::session::priority_file, std::move(callback));
}

bool cli_server::get_id_by_name(const std::string& name, user_id_type& ret)
{
	try
	{
		user_record &record = user_records.at(name);
		if (record.logged_in)
		{
			ret = record.id;
			return true;
		}
	}
	catch (...) {}
	return false;
}

void cli_server::write_data()
{
	std::ofstream fout(data_file, std::ios_base::out | std::ios_base::binary);
	if (!fout.is_open())
		return;
	fout.write(reinterpret_cast<const char*>(&data_ver), sizeof(uint32_t));
	uint32_t size = static_cast<uint32_t>(user_records.size());
	fout.write(reinterpret_cast<char*>(&size), sizeof(uint32_t));
	for (const std::pair<std::string, user_record> &pair : user_records)
	{
		const user_record &user = pair.second;
		size = static_cast<uint32_t>(user.name.size());
		fout.write(reinterpret_cast<char*>(&size), sizeof(uint32_t));
		fout.write(user.name.data(), size);
		fout.write(user.passwd.data(), hash_size);
		size = static_cast<uint32_t>(user.group);
		fout.write(reinterpret_cast<char*>(&size), sizeof(uint32_t));
	}
}

void cli_server::read_data()
{
	if (!fs::exists(data_file))
	{
		write_data();
		return;
	}
	std::ifstream fin(data_file, std::ios_base::in | std::ios_base::binary);

	uint32_t data_file_ver;
	fin.read(reinterpret_cast<char*>(&data_file_ver), sizeof(uint32_t));
	if (data_file_ver != data_ver)
	{
		std::cout << "Incompatible data file.Will not read." << std::endl;
		return;
	}
	uint32_t userCount, size;
	fin.read(reinterpret_cast<char*>(&userCount), sizeof(uint32_t));
	char passwd_buf[hash_size];
	std::vector<char> buf;
	for (; userCount > 0; userCount--)
	{
		user_record user;
		fin.read(reinterpret_cast<char*>(&size), sizeof(uint32_t));
		buf.resize(size);
		fin.read(buf.data(), size);
		user.name = std::string(buf.data(), size);
		fin.read(passwd_buf, hash_size);
		user.passwd = std::string(passwd_buf, hash_size);
		fin.read(reinterpret_cast<char*>(&size), sizeof(uint32_t));
		user.group = static_cast<user_record::group_type>(size);
		user_records.emplace(user.name, user);
	}
}

void cli_server::read_config()
{
	if (!fs::exists(config_file))
		return;
	std::ifstream fin(config_file);

	std::string line;
	std::getline(fin, line);
	while (!fin.eof())
	{
		trim(line);
		if (!line.empty() && line.front() != '#')
		{
			size_t pos = line.find('=');
			if (pos == std::string::npos)
				config_items.emplace(std::move(line), empty_string);
			else
			{
				std::string name = line.substr(0, pos), val = line.substr(pos + 1);
				rtrim(name);
				ltrim(val);
				config_items.emplace(name, val);
			}
		}
		std::getline(fin, line);
	}
}

#define checkErr(x) if (dataItr + (x) > dataEnd) throw(cli_server_error())
#define read_uint(x)												\
	checkErr(size_length);											\
	memcpy(reinterpret_cast<char*>(&(x)), dataItr, size_length);	\
	dataItr += size_length

void cli_server::on_data(user_id_type id, const std::string& data)
{
	try
	{
		const size_t size_length = sizeof(data_size_type);
		const char *dataItr = data.data(), *dataEnd = data.data() + data.size();

		byte type;
		checkErr(1);
		type = *dataItr;
		dataItr += 1;
		switch (type)
		{
			case PAC_TYPE_MSG:
			{
				data_size_type sizeRecv;
				read_uint(sizeRecv);

				checkErr(sizeRecv);
				std::string msg(dataItr, sizeRecv);
				dataItr += sizeRecv;

				on_msg(id, msg);

				break;
			}
			case PAC_TYPE_IMAGE:
			{
				on_image(id, data);
				break;
			}
			case PAC_TYPE_FILE_H:
			{
				on_file_h(id, data);
				break;
			}
			case PAC_TYPE_FILE_B:
			{
				on_file_b(id, data);
				break;
			}
			default:
			{
				user_ext &user = user_exts.at(id);

				if (mode < NORMAL || user.current_stage == user_ext::LOGGED_IN)
					broadcast_data(id, data, msgr_proto::session::priority_file);
				break;
			}
		}
	}
	catch (cli_server_error &)
	{
		if (mode > HARD)
			disconnect(id);
	}
	catch (std::exception &ex)
	{
		std::cerr << ex.what() << std::endl;
		if (mode > HARD)
			disconnect(id);
	}
	catch (...)
	{
		throw;
	}
}

#undef read_uint
#undef checkErr

void cli_server::on_msg(user_id_type id, std::string& msg)
{
	user_ext &user = user_exts.at(id);

	if (mode < NORMAL)
		broadcast_msg(id, msg);
	else
	{
		switch (user.current_stage)
		{
			case user_ext::LOGIN_NAME:
			{
				trim(msg);
				user.name = std::move(msg);

				if (!user_key_storage.on_join(user.name, get_session(id)->get_key()))
				{
					send_msg(id, msg_unauthed_key);
				}
				else
				{
					user.current_stage = user_ext::LOGIN_PASS;
					send_msg(id, msg_input_pass);
				}

				break;
			}
			case user_ext::LOGIN_PASS:
			{
				user.current_stage = user_ext::LOGIN_NAME;
				user_record_list::iterator itr = user_records.find(user.name);
				if (itr != user_records.end())
				{
					user_record &record = itr->second;
					std::string hashed_pass;
					hash(msg, hashed_pass);
					if (record.passwd == hashed_pass)
					{
						//Get user's record linked to id
						record.logged_in = true;
						record.id = id;

						//Send welcome messages
						send_msg(id, msg_welcome);
						m_plugin.on_new_user(user.name);
						//Broadcast user join
						broadcast_msg(server_uid, msg_new_user + user.name + '(' + user.addr + ')');

						//All prepared, mark as LOGGED_IN
						user.current_stage = user_ext::LOGGED_IN;
					}
				}

				if (user.current_stage == user_ext::LOGIN_NAME)
				{
					send_msg(id, msg_input_name);
				}
				break;
			}
			case user_ext::LOGGED_IN:
			{
				std::string tmp(msg);
				trim(tmp);
				if (tmp.front() == '/')
				{
					tmp.erase(0, 1);

					std::string msg_send = process_command(tmp, user_records.at(user.name));
					if (!msg_send.empty())
					{
						send_msg(id, msg_send);
					}
				}
				else
				{
					broadcast_msg(id, msg);
					m_plugin.on_msg(user.name, msg);
				}

				break;
			}
		}
	}
}

void cli_server::on_image(user_id_type id, const std::string& data)
{
	user_ext &user = user_exts.at(id);

	if (mode < NORMAL || user.current_stage == user_ext::LOGGED_IN)
	{
		broadcast_msg(id, empty_string);
		broadcast_data(id, data, msgr_proto::session::priority_msg);
		if (user.current_stage == user_ext::LOGGED_IN)
			m_plugin.on_img(user.name, data.data() + 1 + sizeof(data_size_type), data.size() - (1 + sizeof(data_size_type)));
	}
}

void cli_server::on_file_h(user_id_type id, const std::string& data)
{
	user_ext &user = user_exts.at(id);

	if (mode < NORMAL)
	{
		broadcast_data(id, data, msgr_proto::session::priority_file);
	}
	else if (!user.uploading_key.empty())
	{
		user_key_storage.on_file_h(user.uploading_key, data.data() + 1, data.size() - 1);
	}
	else if (user.current_stage == user_ext::LOGGED_IN)
	{
		m_plugin.on_file_h(user.name, data.data() + 1, data.size() - 1);
	}
}

void cli_server::on_file_b(user_id_type id, const std::string& data)
{
	user_ext &user = user_exts.at(id);

	if (mode < NORMAL)
	{
		broadcast_data(id, data, msgr_proto::session::priority_file);
	}
	else if (!user.uploading_key.empty())
	{
		int ret = user_key_storage.on_file_b(user.uploading_key, data.data() + 1, data.size() - 1);
		switch (ret)
		{
			case 1:
				if (mode > HARD)
					throw(cli_server_error());
			case -1:
				user.uploading_key.clear();
				break;
		}
	}
	else if (user.current_stage == user_ext::LOGGED_IN)
	{
		m_plugin.on_file_b(user.name, data.data() + 1, data.size() - 1);
	}
}

void cli_server::on_join(user_id_type id, const std::string& )
{
	user_ext &ext = user_exts.emplace(id, user_ext()).first->second;
	ext.addr = get_session(id)->get_address();

	if (mode > EASY)
		send_msg(id, msg_input_name);
	else
		broadcast_msg(server_uid, msg_new_user + ext.addr);
}

void cli_server::on_leave(user_id_type id)
{
	user_ext_list::iterator itr = user_exts.find(id);
	user_ext &user = itr->second;

	std::string msg_send(msg_del_user);
	if (mode > EASY)
	{
		if (user.current_stage == user_ext::LOGGED_IN)
		{
			msg_send.append(user.name + '(' + user.addr + ')');
			broadcast_msg(server_uid, msg_send);
			user_record_list::iterator itr = user_records.find(user.name);
			if (itr != user_records.end())
			{
				user_record &record = itr->second;
				record.logged_in = false;
				m_plugin.on_del_user(user.name);
			}
		}
	}
	else
	{
		msg_send.append(user.addr);
		broadcast_msg(server_uid, msg_send);
	}

	user_exts.erase(itr);
}

void cli_server::send_msg(user_id_type id, const std::string& msg)
{
	std::string msg_send(msg);
	insLen(msg_send);
	msg_send.insert(0, 1, PAC_TYPE_MSG);
	send_data(id, msg_send, msgr_proto::session::priority_msg);
}

void cli_server::broadcast_msg(int src, const std::string& msg)
{
	std::string msg_send;
	user_ext &user = user_exts[src];
	if (mode > EASY)
		msg_send = user.name + '(' + user.addr + ')';
	else
		msg_send = user.addr;
	msg_send.push_back(':');
	msg_send.append(msg);
	//Let plugins log server messages as it won't go through on_msg
	if (mode > EASY && src == server_uid)
		m_plugin.on_msg(server_uname, msg);

	insLen(msg_send);
	msg_send.insert(0, 1, PAC_TYPE_MSG);
	broadcast_data(src, msg_send, msgr_proto::session::priority_msg);
}

void cli_server::broadcast_data(int src, const std::string& data, int priority)
{
	for (const std::pair<int, user_ext> &p : user_exts)
	{
		int target = p.first;
		if (target != src && (mode < NORMAL || p.second.current_stage == user_ext::LOGGED_IN))
		{
			send_data(static_cast<user_id_type>(target), data, priority);
		}
	}
}

std::string cli_server::process_command(std::string& cmd, user_record& user)
{
	static const msg_server_plugin::user_type user_type_table[] = {
		msg_server_plugin::user_type::GUEST,
		msg_server_plugin::user_type::USER,
		msg_server_plugin::user_type::ADMIN,
		msg_server_plugin::user_type::CONSOLE,
	};
	user_record::group_type group = user.group;
	std::string ret;

	size_t pos = cmd.find(' ');
	std::string args;
	if (pos != std::string::npos)
	{
		args.assign(cmd, pos + 1, std::string::npos);
		cmd.erase(pos);
		trim(args);
	}
	
	if (cmd == "op")
	{
		if (group >= user_record::ADMIN)
		{
			user_record_list::iterator itr = user_records.find(args);
			if (itr != user_records.end())
			{
				itr->second.group = user_record::ADMIN;
				main_iosrv.post([this]() {
					write_data();
				});
				ret = "Opped " + itr->second.name;
			}
		}
	}
	else if (cmd == "reg")
	{
		if (group >= user_record::ADMIN)
		{
			pos = args.find(' ');
			if (pos != std::string::npos)
			{
				cmd = args.substr(0, pos);
				args.erase(0, pos);
				trim(cmd);
				trim(args);
				std::string hashed_passwd;
				hash(args, hashed_passwd);

				user_record_list::iterator itr = user_records.find(cmd);
				if (itr == user_records.end())
				{
					user_records.emplace(cmd, user_record(cmd, hashed_passwd, user_record::USER));
					main_iosrv.post([this]() {
						write_data();
					});
					ret = "Registered " + cmd;
				}
			}
		}
	}
	else if (cmd == "reg_key")
	{
		if (user_key_storage.storage_available())
		{
			if (args.empty() || group >= user_record::ADMIN)
			{
				if (args.empty())
					args = user.name;
				user_record_list::iterator itr = user_records.find(args);
				if (itr != user_records.end())
				{
					user_record &up_user = itr->second;
					if (up_user.logged_in)
						user_exts.at(up_user.id).uploading_key = args;
				}
			}
		}
	}
	else if (cmd == "unreg")
	{
		if (group >= user_record::ADMIN)
		{
			user_record_list::iterator itr = user_records.find(args);
			if (itr != user_records.end())
			{
				user_records.erase(itr);
				main_iosrv.post([this]() {
					write_data();
				});
				ret = "Unregistered " + args;
			}
		}
	}
	else if (cmd == "changepass")
	{
		user.passwd.clear();
		hash(args, user.passwd);
		main_iosrv.post([this]() {
			write_data();
		});
		ret = "Password changed";
	}
	else if (cmd == "con")
	{
		if (group >= user_record::ADMIN)
		{
			ret = "Connecting";
			connect(args, portConnect);
		}
	}
	else if (cmd == "list")
	{
		if (group >= user_record::USER)
		{
			for (const std::pair<int, user_ext> &p : user_exts)
			{
				if (p.first == server_uid)
					continue;
				ret.append(p.second.name);
				ret.push_back(';');
			}
			ret.pop_back();
		}
	}
	else if (cmd == "stop")
	{
		if (group >= user_record::CONSOLE)
		{
			server_on = false;
			exit_promise.set_value();
			ret = "Stopping server";
		}
	}
	else
	{
		m_plugin.on_cmd(user.name, user_type_table[group], cmd, args);
	}
	return ret;
}

bool cli_server::new_rand_port(port_type& ret)
{
	if (static_port != -1)
		ret = static_cast<port_type>(static_port);
	else
	{
		if (ports.empty())
			return false;
		std::list<port_type>::iterator portItr = ports.begin();
		for (int i = std::rand() % ports.size(); i > 0; i--)
			portItr++;
		ret = *portItr;
		ports.erase(portItr);
	}
	return true;
}

void cli_server::on_exit()
{
	broadcast_msg(server_uid, "Stopping");
	try
	{
		for (const std::pair<int, user_ext> &p : user_exts)
		{
			try
			{
				m_plugin.on_del_user(p.second.name);
			}
			catch (...) {}
		}
	}
	catch (...) {}
}

void print_usage()
{
	std::cout << "Usage:" << std::endl;
	std::cout << "\tmessenger_server [mode=relay|center] [port=****] [ports=****[-****]]" << std::endl;
}

int main(int argc, char *argv[])
{
#ifdef NDEBUG
	try
	{
#endif
		initKey();

		cli_server::read_config();
		for (int i = 1; i < argc; i++)
		{
			std::string arg(argv[i]);
			size_t pos = arg.find('=');
			if (pos == std::string::npos)
				config_items[std::move(arg)] = empty_string;
			else
				config_items[arg.substr(0, pos)] = arg.substr(pos + 1);
		}

		port_type portListener = 4826;
		port_type portsBegin = 5000, portsEnd = 9999;
		bool use_v6 = false;
		int crypto_worker = 1;

		//Load necessary args for the construction of cli_server
		try
		{
			std::string &arg = config_items.at("port");
			portListener = static_cast<port_type>(std::stoi(arg));
			std::cout << "Listening " << arg << std::endl;
		}
		catch (std::out_of_range &) { portListener = 4826; }
		catch (std::invalid_argument &) { portListener = 4826; }
		try
		{
			config_items.at("usev6");
			use_v6 = true;
			std::cout << "Using IPv6 for listening" << std::endl;
		}
		catch (std::out_of_range &) {}
		try
		{
			std::string &arg = config_items.at("crypto_worker");
			crypto_worker = std::stoi(arg);
			std::cout << "Using " << crypto_worker << " crypto worker(s)" << std::endl;
		}
		catch (std::out_of_range &) {}

		crypto_srv = std::make_unique<crypto::server>(cryp_iosrv, crypto_worker);
		srv = std::make_unique<cli_server>
			(main_iosrv, misc_iosrv, asio::ip::tcp::endpoint((use_v6 ? asio::ip::tcp::v6() : asio::ip::tcp::v4()), portListener), *crypto_srv.get());

		try
		{
			std::string &arg = config_items.at("mode");
			if (arg == "strict")
				srv->set_mode(HARD);
			else if (arg == "normal" || arg == "center" || arg == "centre")
				srv->set_mode(NORMAL);
			else if (arg == "relay")
				srv->set_mode(EASY);
			else
				throw(std::out_of_range(""));
			std::cout << "Mode set to " << arg << std::endl;
		}
		catch (std::out_of_range &) {}
		try
		{
			std::string &arg = config_items.at("ports");
			size_t pos = arg.find('-');
			if (pos == std::string::npos)
			{
				srv->set_static_port(static_cast<port_type>(std::stoi(arg)));
				portsBegin = 1;
				portsEnd = 0;
				std::cout << "Connecting port set to " << arg << std::endl;
			}
			else
			{
				std::string ports_begin = arg.substr(0, pos), ports_end = arg.substr(pos + 1);
				portsBegin = static_cast<port_type>(std::stoi(ports_begin));
				portsEnd = static_cast<port_type>(std::stoi(ports_end));
				srv->set_static_port(-1);
				std::cout << "Connecting ports set to " << arg << std::endl;
			}
		}
		catch (std::out_of_range &) { portsBegin = 5000, portsEnd = 9999; }
		catch (std::invalid_argument &) { portsBegin = 5000, portsEnd = 9999; }

		m_plugin.new_plugin<msg_logger>();
		m_plugin.new_plugin<server_mail>();
		m_plugin.new_plugin<file_storage>();
		m_plugin.init(config_items);
		user_key_storage.init(config_items);

		std::srand(static_cast<unsigned int>(std::time(NULL)));
		for (; portsBegin <= portsEnd; portsBegin++)
			srv->free_rand_port(portsBegin);

		auto iosrv_thread = [](asio::io_service *iosrv) {
			bool abnormally_exit;
			do
			{
				abnormally_exit = false;
				try
				{
					iosrv->run();
				}
				catch (...) { abnormally_exit = true; }
			} while (abnormally_exit);
		};
		std::shared_ptr<asio::io_service::work> main_iosrv_work = std::make_shared<asio::io_service::work>(main_iosrv);
		std::shared_ptr<asio::io_service::work> misc_iosrv_work = std::make_shared<asio::io_service::work>(misc_iosrv);
		std::shared_ptr<asio::io_service::work> cryp_iosrv_work = std::make_shared<asio::io_service::work>(cryp_iosrv);
		std::thread main_iosrv_thread(iosrv_thread, &main_iosrv);
		main_iosrv_thread.detach();
		std::thread misc_iosrv_thread(iosrv_thread, &misc_iosrv);
		misc_iosrv_thread.detach();
		std::thread cryp_iosrv_thread(iosrv_thread, &cryp_iosrv);
		cryp_iosrv_thread.detach();

		srv->start();

		std::thread input_thread([]() {
			user_record user_root;
			user_root.name = "Server";
			user_root.group = user_record::CONSOLE;
			std::string command;
			while (server_on)
			{
				std::getline(std::cin, command);
				std::string ret = srv->process_command(command, user_root);
				if (!ret.empty())
					std::cout << ret << std::endl;
			}
		});
		input_thread.detach();

		std::future<void> future = exit_promise.get_future();
		future.wait();
		
		srv->on_exit();
		m_plugin.on_exit();
		srv->shutdown();
		
		misc_iosrv_work.reset();
		while (!misc_iosrv.stopped());

		main_iosrv_work.reset();
		while (!main_iosrv.stopped());

		crypto_srv->stop();

		cryp_iosrv_work.reset();
		while (!cryp_iosrv.stopped());

		srv.reset();
		crypto_srv.reset();
#ifdef NDEBUG
	}
	catch (std::exception& e)
	{
		std::cerr << "Exception: " << e.what() << std::endl;
	}
#endif
	return 0;
}
