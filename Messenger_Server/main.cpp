#include "stdafx.h"
#include "global.h"
#include "crypto.h"
#include "session.h"
#include "plugin.h"
#include "main.h"

const std::string empty_string;

std::promise<void> exit_promise;
config_table_tp config_items;

asio::io_service main_io_service, misc_io_service;
cli_server_interface inter;
cli_plugin_interface i_plugin;
plugin_manager m_plugin(i_plugin);
volatile bool server_on = true;

const char *msg_new_user = "New user:", *msg_del_user = "Leaving user:";
const char *msg_input_name = "Username:", *msg_input_pass = "Password:", *msg_welcome = "Welcome";

const char* privatekeyFile = ".privatekey";

bool cli_plugin_interface::get_id_by_name(const std::string &name, user_id_type &id)
{
	return inter.get_id_by_name(name, id);
}

void cli_plugin_interface::broadcast_msg(const std::string &msg)
{
	inter.broadcast_msg(server_uid, msg);
}

void cli_plugin_interface::send_msg(user_id_type id, const std::string &msg)
{
	inter.send_msg(id, msg);
}

void cli_plugin_interface::send_image(user_id_type id, const std::string &path)
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
	inter.send_data(id, img_buf, msgr_proto::session::priority_msg);
}

bool cli_server_interface::get_id_by_name(const std::string &name, user_id_type &ret)
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

void cli_server_interface::write_data()
{
	std::ofstream fout(data_file, std::ios_base::out | std::ios_base::binary);
	if (!fout.is_open())
		return;
	fout.write(reinterpret_cast<const char*>(&data_ver), sizeof(uint32_t));
	uint32_t size = user_records.size();
	fout.write(reinterpret_cast<char*>(&size), sizeof(uint32_t));
	for (const std::pair<std::string, user_record> &pair : user_records)
	{
		const user_record &user = pair.second;
		size = user.name.size();
		fout.write(reinterpret_cast<char*>(&size), sizeof(uint32_t));
		fout.write(user.name.data(), size);
		fout.write(user.passwd.data(), hash_size);
		size = static_cast<uint32_t>(user.group);
		fout.write(reinterpret_cast<char*>(&size), sizeof(uint32_t));
	}
}

void cli_server_interface::read_data()
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
	for (; userCount > 0; userCount--)
	{
		user_record user;
		fin.read(reinterpret_cast<char*>(&size), sizeof(uint32_t));
		std::unique_ptr<char[]> buf = std::make_unique<char[]>(size);
		fin.read(buf.get(), size);
		user.name = std::string(buf.get(), size);
		fin.read(passwd_buf, hash_size);
		user.passwd = std::string(passwd_buf, hash_size);
		fin.read(reinterpret_cast<char*>(&size), sizeof(uint32_t));
		user.group = static_cast<user_record::group_type>(size);
		user_records.emplace(user.name, user);
	}
}

void cli_server_interface::read_config()
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

#define checkErr(x) if (dataItr + (x) > dataEnd) throw(0)
#define read_uint(x)												\
	checkErr(size_length);											\
	memcpy(reinterpret_cast<char*>(&(x)), dataItr, size_length);	\
	dataItr += size_length

void cli_server_interface::on_data(user_id_type id, const std::string &data)
{
	try
	{
		const size_t size_length = sizeof(data_length_type);
		const char *dataItr = data.data(), *dataEnd = data.data() + data.size();

		byte type;
		checkErr(1);
		type = *dataItr;
		dataItr += 1;
		switch (type)
		{
			case PAC_TYPE_MSG:
			{
				data_length_type sizeRecv;
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
			default:
			{
				user_ext &user = user_exts.at(id);

				if (mode != CENTER || user.current_stage == user_ext::LOGGED_IN)
					broadcast_data(id, data, msgr_proto::session::priority_file);
				break;
			}
		}
	}
	catch (std::exception ex)
	{
		std::cerr << ex.what() << std::endl;
	}
	catch (int)
	{
	}
	catch (...)
	{
		throw;
	}
}

#undef checkErr
#undef read_uint

void cli_server_interface::on_msg(user_id_type id, std::string &msg)
{
	user_ext &user = user_exts.at(id);

	if (mode != CENTER)
		broadcast_msg(id, msg);
	else
	{
		switch (user.current_stage)
		{
			case user_ext::LOGIN_NAME:
			{
				trim(msg);
				user.name = std::move(msg);
				user.current_stage = user_ext::LOGIN_PASS;

				send_msg(id, msg_input_pass);
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
						broadcast_msg(server_uid, msg_new_user + user.name + '(' + user.addr + ')');

						send_msg(id, msg_welcome);

						user.current_stage = user_ext::LOGGED_IN;
						record.logged_in = true;
						record.id = id;

						m_plugin.on_new_user(user.name);
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

					std::string msg_send = process_command(tmp, user_records[user.name]);
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

void cli_server_interface::on_image(user_id_type id, const std::string &data)
{
	user_ext &user = user_exts.at(id);

	if (mode != CENTER || user.current_stage == user_ext::LOGGED_IN)
	{
		if (mode != CENTER || user.current_stage == user_ext::LOGGED_IN)
		{
			broadcast_msg(id, empty_string);
			broadcast_data(id, data, msgr_proto::session::priority_msg);
			m_plugin.on_img(user.name, data.data() + 1 + sizeof(data_length_type), data.size() - (1 + sizeof(data_length_type)));
		}
	}
}

void cli_server_interface::on_join(user_id_type id, const std::string &)
{
	user_ext &ext = user_exts.emplace(id, user_ext()).first->second;
	ext.addr = srv->get_session(id)->get_address();

	if (mode == CENTER)
		send_msg(id, msg_input_name);
	else
		broadcast_msg(server_uid, msg_new_user + ext.addr);
}

void cli_server_interface::on_leave(user_id_type id)
{
	user_ext_list::iterator itr = user_exts.find(id);
	user_ext &user = itr->second;

	std::string msg_send(msg_del_user);
	if (mode == CENTER)
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

void cli_server_interface::send_msg(user_id_type id, const std::string &msg)
{
	std::string msg_send(msg);
	insLen(msg_send);
	msg_send.insert(0, 1, PAC_TYPE_MSG);
	send_data(id, msg_send, msgr_proto::session::priority_msg);
}

void cli_server_interface::broadcast_msg(int src, const std::string &msg)
{
	std::string msg_send;
	user_ext &user = user_exts[src];
	if (mode == CENTER)
		msg_send = user.name + '(' + user.addr + ')';
	else
		msg_send = user.addr;
	msg_send.push_back(':');
	msg_send.append(msg);
	if (mode == CENTER && !msg.empty())
		m_plugin.on_msg(server_uname, msg);

	insLen(msg_send);
	msg_send.insert(0, 1, PAC_TYPE_MSG);
	broadcast_data(src, msg_send, msgr_proto::session::priority_msg);
}

void cli_server_interface::broadcast_data(int src, const std::string &data, int priority)
{
	for (const std::pair<int, user_ext> &p : user_exts)
	{
		int target = p.first;
		if (target != src && (mode != CENTER || p.second.current_stage == user_ext::LOGGED_IN))
		{
			send_data(static_cast<user_id_type>(target), data, priority);
		}
	}
}

std::string cli_server_interface::process_command(std::string cmd, user_record &user)
{
	user_record::group_type group = user.group;
	std::string ret;

	int pos = cmd.find(' ');
	std::string args;
	if (pos != std::string::npos)
	{
		args.assign(cmd, pos + 1, std::string::npos);
		cmd.erase(pos);
	}
	trim(args);
	
	if (cmd == "op")
	{
		if (group >= user_record::ADMIN)
		{
			user_record_list::iterator itr = user_records.find(args);
			if (itr != user_records.end())
			{
				itr->second.group = user_record::ADMIN;
				main_io_service.post([this]() {
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
					main_io_service.post([this]() {
						write_data();
					});
					ret = "Registered " + cmd;
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
				main_io_service.post([this]() {
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
		main_io_service.post([this]() {
			write_data();
		});
		ret = "Password changed";
	}
	else if (cmd == "con")
	{
		if (group >= user_record::ADMIN)
		{
			ret = "Connecting";
			srv->connect(args, portConnect);
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
	return ret;
}

bool cli_server_interface::new_rand_port(port_type &ret)
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

void cli_server_interface::on_exit()
{
	try
	{
		for (const std::pair<int, user_ext> &p : user_exts)
		{
			m_plugin.on_del_user(p.second.name);
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

		try
		{
			std::string &arg = config_items.at("mode");
			if (arg == "center" || arg == "centre")
				inter.set_mode(CENTER);
			else if (arg == "relay")
				inter.set_mode(RELAY);
			else
				throw(0);
			std::cout << "Mode set to " << arg << std::endl;
		}
		catch (int) {}
		catch (std::out_of_range &) {}
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
			std::string &arg = config_items.at("ports");
			size_t pos = arg.find('-');
			if (pos == std::string::npos)
			{
				inter.set_static_port(static_cast<port_type>(std::stoi(arg)));
				portsBegin = 1;
				portsEnd = 0;
				std::cout << "Connecting port set to " << arg << std::endl;
			}
			else
			{
				std::string ports_begin = arg.substr(0, pos), ports_end = arg.substr(pos + 1);
				portsBegin = static_cast<port_type>(std::stoi(ports_begin));
				portsEnd = static_cast<port_type>(std::stoi(ports_end));
				inter.set_static_port(-1);
				std::cout << "Connecting ports set to " << arg << std::endl;
			}
		}
		catch (std::out_of_range &) { portsBegin = 5000, portsEnd = 9999; }
		catch (std::invalid_argument &) { portsBegin = 5000, portsEnd = 9999; }
		try
		{
			config_items.at("usev6");
			use_v6 = true;
			std::cout << "Using IPv6 for listening" << std::endl;
		}
		catch (std::out_of_range &) {}

		m_plugin.new_plugin<msg_logger>();
		m_plugin.init(config_items);

		std::srand(static_cast<unsigned int>(std::time(NULL)));
		for (; portsBegin <= portsEnd; portsBegin++)
			inter.free_rand_port(portsBegin);

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
		std::shared_ptr<asio::io_service::work> main_iosrv_work = std::make_shared<asio::io_service::work>(main_io_service);
		std::shared_ptr<asio::io_service::work> misc_iosrv_work = std::make_shared<asio::io_service::work>(misc_io_service);
		std::thread main_iosrv_thread(iosrv_thread, &main_io_service);
		main_iosrv_thread.detach();
		std::thread misc_iosrv_thread(iosrv_thread, &misc_io_service);
		misc_iosrv_thread.detach();

		std::unique_ptr<msgr_proto::server> srv = std::make_unique<msgr_proto::server>
			(main_io_service, misc_io_service, inter, asio::ip::tcp::endpoint((use_v6 ? asio::ip::tcp::v6() : asio::ip::tcp::v4()), portListener));
		std::thread input_thread([]() {
			user_record user_root;
			user_root.name = "Server";
			user_root.group = user_record::CONSOLE;
			std::string command;
			while (server_on)
			{
				std::getline(std::cin, command);
				std::string ret = inter.process_command(command, user_root);
				if (!ret.empty())
					std::cout << ret << std::endl;
			}
		});
		input_thread.detach();

		std::future<void> future = exit_promise.get_future();
		future.wait();

		misc_iosrv_work.reset();
		misc_io_service.stop();

		main_iosrv_work.reset();
		main_io_service.stop();

		inter.on_exit();
		m_plugin.on_exit();
#ifdef NDEBUG
	}
	catch (std::exception& e)
	{
		std::cerr << "Exception: " << e.what() << "\n";
	}
#endif
	return 0;
}
