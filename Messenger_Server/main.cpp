#include "stdafx.h"
#include "global.h"
#include "crypto.h"
#include "session.h"
#include "main.h"

asio::io_service main_io_service, misc_io_service;
server *srv;
cli_server_interface inter;
volatile bool server_on = true;

user_record_list user_records;
user_ext_list user_exts;

const char *config_file = ".config";
const char *msg_new_user = "New user:", *msg_del_user = "Leaving user:";
const char *msg_input_name = "Username:", *msg_input_pass = "Password:", *msg_welcome = "Welcome";

modes mode = RELAY;

void write_config()
{
	std::ofstream fout(config_file, std::ios_base::out | std::ios_base::binary);
	if (!fout.is_open())
		return;
	size_t size = user_records.size();
	fout.write(reinterpret_cast<char*>(&size), sizeof(size_t));
	std::for_each(user_records.begin(), user_records.end(), [&size, &fout](const std::pair<std::string, user_record> &pair) {
		const user_record &usr = pair.second;
		size = usr.name.size();
		fout.write(reinterpret_cast<char*>(&size), sizeof(size_t));
		fout.write(usr.name.data(), size);
		fout.write(usr.passwd.data(), hash_size);
		size = static_cast<size_t>(usr.group);
		fout.write(reinterpret_cast<char*>(&size), sizeof(size_t));
	});
}

void read_config()
{
	if (!fs::exists(config_file))
	{
		write_config();
		return;
	}
	std::ifstream fin(config_file, std::ios_base::in | std::ios_base::binary);

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
			case pac_type_msg:
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
							msg_send.insert(0, 1, pac_type_msg);
							srv->send_data(id, msg_send, session::priority_msg);
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
									msg_send.insert(0, 1, pac_type_msg);
									srv->send_data(id, msg_send, session::priority_msg);

									usr.current_stage = user_ext::LOGGED_IN;
								}
							}

							if (usr.current_stage == user_ext::LOGIN_NAME)
							{
								std::string msg_send(msg_input_name);
								insLen(msg_send);
								msg_send.insert(0, 1, pac_type_msg);
								srv->send_data(id, msg_send, session::priority_msg);
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
									msg_send.insert(0, 1, pac_type_msg);
									srv->send_data(id, msg_send, session::priority_msg);
								}
							}
							else
								broadcast_msg(id, msg);

							break;
						}
					}
				}

				break;
			}
			default:
			{
				if (mode != CENTER || usr.current_stage == user_ext::LOGGED_IN)
					broadcast_data(id, data, session::priority_file);
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
		msg_send.insert(0, 1, pac_type_msg);
		srv->send_data(id, msg_send, session::priority_msg);
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

void cli_server_interface::broadcast_msg(user_id_type src, const std::string &msg)
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
	msg_send.insert(0, 1, pac_type_msg);
	broadcast_data(src, msg_send, session::priority_msg);
}

void cli_server_interface::broadcast_data(user_id_type src, const std::string &data, int priority)
{
	std::for_each(user_exts.begin(), user_exts.end(), [src, &data, priority](const std::pair<int, user_ext> &p) {
		user_id_type target = p.first;
		if (target != src && (mode != CENTER || p.second.current_stage == user_ext::LOGGED_IN))
		{
			misc_io_service.post([target, data, priority]() {
				srv->send_data(target, data, priority);
			});
		}
	});
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
		if (group == user_record::ADMIN)
		{
			user_record_list::iterator itr = user_records.find(args);
			if (itr != user_records.end())
			{
				itr->second.group = user_record::ADMIN;
				main_io_service.post([this]() {
					write_config();
				});
				ret = "Opped " + itr->second.name;
			}
		}
	}
	else if (cmd == "reg")
	{
		if (group == user_record::ADMIN)
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
						write_config();
					});
					ret = "Registered " + cmd;
				}
			}
		}
	}
	else if (cmd == "unreg")
	{
		if (group == user_record::ADMIN)
		{
			user_record_list::iterator itr = user_records.find(args);
			if (itr != user_records.end())
			{
				user_records.erase(itr);
				main_io_service.post([this]() {
					write_config();
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
			write_config();
		});
		ret = "Password changed";
	}
	else if (cmd == "con")
	{
		if (group == user_record::ADMIN)
		{
			ret = "Connecting";
			srv->connect(args, portConnect);
		}
	}
	else if (cmd == "stop")
	{
		if (group == user_record::ADMIN)
		{
			server_on = false;
		}
	}
	return ret;
}

bool cli_server_interface::new_rand_port(port_type &ret)
{
	if (static_port != -1)
		ret = static_port;
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
		port_type portListener = 4826;
		port_type portsBegin = 5000, portsEnd = 9999;
		bool use_v6 = false;

		for (int i = 1; i < argc; i++)
		{
			std::string arg(argv[i]);
			if (arg.substr(0, 5) == "mode=")
			{
				arg.erase(0, 5);
				if (arg == "center" || arg == "centre")
					mode = CENTER;
				else if (arg == "relay")
					mode = RELAY;
				else
				{
					print_usage();
					return 0;
				}
			}
			else if (arg.substr(0, 5) == "port=")
			{
				try
				{
					portListener = std::stoi(arg.substr(5));
				}
				catch (std::invalid_argument &)
				{
					print_usage();
					return 0;
				}
			}
			else if (arg.substr(0, 6) == "ports=")
			{
				int pos = arg.find('-', 6);
				if (pos == std::string::npos)
				{
					try
					{
						inter.set_static_port(std::stoi(arg.substr(6)));
					}
					catch (std::invalid_argument &)
					{
						print_usage();
						return 0;
					}
					portsBegin = 1;
					portsEnd = 0;
				}
				else
				{
					std::string ports_begin = arg.substr(6, pos - 6), ports_end = arg.substr(pos + 1);
					try
					{
						portsBegin = std::stoi(ports_begin);
						portsEnd = std::stoi(ports_end);
					}
					catch (std::invalid_argument &)
					{
						print_usage();
						return 0;
					}
					inter.set_static_port(-1);
				}
			}
			else if (arg == "usev6")
			{
				use_v6 = true;
			}
			else
			{
				print_usage();
				return 0;
			}
		}
		std::srand(static_cast<unsigned int>(std::time(NULL)));

		read_config();

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

		user_exts[-1].name = user_exts[-1].addr = "Server";
		user_record user_root;
		user_root.name = "Server";
		user_root.group = user_record::ADMIN;

		srv = new server(main_io_service, misc_io_service, inter, asio::ip::tcp::endpoint((use_v6 ? asio::ip::tcp::v6() : asio::ip::tcp::v4()), portListener));
		std::string command;
		while (server_on)
		{
			std::getline(std::cin, command);
			std::cout << inter.process_command(command, user_root) << std::endl;
		}

		write_config();

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
