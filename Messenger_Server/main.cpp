#include "stdafx.h"
#include "global.h"
#include "crypto.h"
#include "session.h"
#include "plugin.h"
#include "main.h"

std::string empty_string;

std::promise<void> exit_promise;
config_table_tp config_items;

asio::io_service main_io_service, misc_io_service;
cli_server_interface inter;
plugin_manager plugin_m;
volatile bool server_on = true;

const char *msg_new_user = "New user:", *msg_del_user = "Leaving user:";
const char *msg_input_name = "Username:", *msg_input_pass = "Password:", *msg_welcome = "Welcome";

void cli_server_interface::write_data()
{
	std::ofstream fout(data_file, std::ios_base::out | std::ios_base::binary);
	if (!fout.is_open())
		return;
	fout.write(reinterpret_cast<const char*>(&data_ver), sizeof(uint32_t));
	size_t size = user_records.size();
	fout.write(reinterpret_cast<char*>(&size), sizeof(size_t));
	for (const std::pair<std::string, user_record> &pair : user_records)
	{
		const user_record &usr = pair.second;
		size = usr.name.size();
		fout.write(reinterpret_cast<char*>(&size), sizeof(size_t));
		fout.write(usr.name.data(), size);
		fout.write(usr.passwd.data(), hash_size);
		size = static_cast<size_t>(usr.group);
		fout.write(reinterpret_cast<char*>(&size), sizeof(size_t));
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
	size_t userCount, size;
	fin.read(reinterpret_cast<char*>(&userCount), sizeof(size_t));
	char passwd_buf[hash_size];
	for (; userCount > 0; userCount--)
	{
		user_record usr;
		fin.read(reinterpret_cast<char*>(&size), sizeof(size_t));
		char* buf = new char[size];
		fin.read(buf, size);
		usr.name = std::string(buf, size);
		delete[] buf;
		fin.read(passwd_buf, hash_size);
		usr.passwd = std::string(passwd_buf, hash_size);
		fin.read(reinterpret_cast<char*>(&size), sizeof(size_t));
		usr.group = static_cast<user_record::group_type>(size);
		user_records.emplace(usr.name, usr);
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
		user_ext &usr = user_exts.at(id);

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

				if (mode != CENTER)
					broadcast_msg(id, msg);
				else
				{
					switch (usr.current_stage)
					{
						case user_ext::LOGIN_NAME:
						{
							trim(msg);
							usr.name = std::move(msg);
							usr.current_stage = user_ext::LOGIN_PASS;
							
							std::string msg_send(msg_input_pass);
							insLen(msg_send);
							msg_send.insert(0, 1, PAC_TYPE_MSG);
							srv->send_data(id, msg_send, msgr_proto::session::priority_msg);
							break;
						}
						case user_ext::LOGIN_PASS:
						{
							usr.current_stage = user_ext::LOGIN_NAME;
							user_record_list::iterator itr = user_records.find(usr.name);
							if (itr != user_records.end())
							{
								trim(msg);
								std::string tmp;
								hash(msg, tmp);
								if (itr->second.passwd == tmp)
								{
									broadcast_msg(-1, msg_new_user + usr.name + '(' + usr.addr + ')');

									std::string msg_send(msg_welcome);
									insLen(msg_send);
									msg_send.insert(0, 1, PAC_TYPE_MSG);
									srv->send_data(id, msg_send, msgr_proto::session::priority_msg);

									usr.current_stage = user_ext::LOGGED_IN;
								}
							}

							if (usr.current_stage == user_ext::LOGIN_NAME)
							{
								std::string msg_send(msg_input_name);
								insLen(msg_send);
								msg_send.insert(0, 1, PAC_TYPE_MSG);
								srv->send_data(id, msg_send, msgr_proto::session::priority_msg);
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

								std::string msg_send = process_command(tmp, user_records[usr.name]);
								if (!msg_send.empty())
								{
									insLen(msg_send);
									msg_send.insert(0, 1, PAC_TYPE_MSG);
									srv->send_data(id, msg_send, msgr_proto::session::priority_msg);
								}
							}
							else
							{
								broadcast_msg(id, msg);
								plugin_m.on_msg(usr.name, msg);
							}

							break;
						}
					}
				}

				break;
			}
			case PAC_TYPE_IMAGE:
			{
				if (mode != CENTER || usr.current_stage == user_ext::LOGGED_IN)
				{
					broadcast_msg(id, "");
					broadcast_data(id, data, msgr_proto::session::priority_msg);
					plugin_m.on_img(usr.name, data.data() + 1 + sizeof(data_length_type), data.size() - (1 + sizeof(data_length_type)));
				}
				break;
			}
			default:
			{
				if (mode != CENTER || usr.current_stage == user_ext::LOGGED_IN)
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

void cli_server_interface::on_join(user_id_type id)
{
	user_ext &ext = user_exts.emplace(id, user_ext()).first->second;
	ext.addr = srv->get_session(id)->get_address();

	if (mode == CENTER)
	{
		std::string msg_send(msg_input_name);
		insLen(msg_send);
		msg_send.insert(0, 1, PAC_TYPE_MSG);
		srv->send_data(id, msg_send, msgr_proto::session::priority_msg);
	}
	else
		broadcast_msg(-1, msg_new_user + ext.addr);
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
			broadcast_msg(-1, msg_send);
		}
	}
	else
	{
		msg_send.append(user.addr);
		broadcast_msg(-1, msg_send);
	}

	user_exts.erase(itr);
}

void cli_server_interface::broadcast_msg(int src, const std::string &msg)
{
	std::string msg_send;
	user_ext &usr = user_exts[src];
	if (mode == CENTER)
		msg_send = usr.name + '(' + usr.addr + ')';
	else
		msg_send = usr.addr;
	msg_send.push_back(':');
	msg_send.append(msg);

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
			misc_io_service.post([this, target, data, priority]() {
				srv->send_data(static_cast<user_id_type>(target), data, priority);
			});
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

		plugin_m.new_plugin(std::make_unique<msg_logger>());
		plugin_m.init(config_items);

		std::srand(static_cast<unsigned int>(std::time(NULL)));

		std::shared_ptr<asio::io_service::work> main_iosrv_work = std::make_shared<asio::io_service::work>(main_io_service);
		std::thread main_iosrv_thread([]() {
			bool abnormally_exit;
			do
			{
				abnormally_exit = false;
				try
				{
					main_io_service.run();
				}
				catch (...) { abnormally_exit = true; }
			} while (abnormally_exit);
		});
		main_iosrv_thread.detach();

		std::shared_ptr<asio::io_service::work> misc_iosrv_work = std::make_shared<asio::io_service::work>(misc_io_service);
		std::thread misc_iosrv_thread([]() {
			bool abnormally_exit;
			do
			{
				abnormally_exit = false;
				try
				{
					misc_io_service.run();
				}
				catch (...) { abnormally_exit = true; }
			} while (abnormally_exit);
		});
		misc_iosrv_thread.detach();

		for (; portsBegin <= portsEnd; portsBegin++)
			inter.free_rand_port(portsBegin);

		user_record user_root;
		user_root.name = "Server";
		user_root.group = user_record::CONSOLE;

		std::unique_ptr<msgr_proto::server> srv = std::make_unique<msgr_proto::server>
			(main_io_service, misc_io_service, inter, asio::ip::tcp::endpoint((use_v6 ? asio::ip::tcp::v6() : asio::ip::tcp::v4()), portListener));
		std::thread input_thread([&user_root]() {
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
#ifdef NDEBUG
	}
	catch (std::exception& e)
	{
		std::cerr << "Exception: " << e.what() << "\n";
	}
#endif
	return 0;
}
