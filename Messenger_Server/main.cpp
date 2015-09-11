#include "stdafx.h"
#include "global.h"
#include "crypto.h"
#include "session.h"
#include "main.h"

net::io_service main_io_service, misc_io_service;
server *srv;
cli_server_interface inter;
volatile bool server_on = true;

user_log_list user_logs;
user_ext_list user_ext;

const char *config_file = ".config";
const char *msg_new_user = "New user:", *msg_del_user = "Leaving user:";
const char *msg_input_name = "Username:", *msg_input_pass = "Password:", *msg_welcome = "Welcome";

modes mode = RELAY;

void write_config()
{
	std::ofstream fout(config_file, std::ios_base::out | std::ios_base::binary);
	if (!fout.is_open())
		return;
	size_t size = user_logs.size();
	fout.write(reinterpret_cast<char*>(&size), sizeof(size_t));
	std::for_each(user_logs.begin(), user_logs.end(), [&size, &fout](const std::pair<std::string, user_log> &pair) {
		const user_log &usr = pair.second;
		size = usr.name.size();
		fout.write(reinterpret_cast<char*>(&size), sizeof(size_t));
		fout.write(usr.name.data(), size);
		fout.write(usr.passwd.data(), sha256_size);
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
	char passwd_buf[sha256_size];
	for (; userCount > 0; userCount--)
	{
		user_log usr;
		fin.read(reinterpret_cast<char*>(&size), sizeof(size_t));
		char* buf = new char[size];
		fin.read(buf, size);
		usr.name = std::string(buf, size);
		delete[] buf;
		fin.read(passwd_buf, sha256_size);
		usr.passwd = std::string(passwd_buf, sha256_size);
		fin.read(reinterpret_cast<char*>(&size), sizeof(size_t));
		usr.group = static_cast<user_log::group_type>(size);
		user_logs.emplace(usr.name, usr);
	}
}

#define checkErr(x) if (dataItr + (x) > dataEnd) throw(0)
#define read_uint(x)												\
	checkErr(size_length);											\
	memcpy(reinterpret_cast<char*>(&(x)), dataItr, size_length);	\
	dataItr += size_length

void cli_server_interface::on_data(id_type id, const std::string &data)
{
	try
	{
		const size_t size_length = sizeof(data_length_type);
		const char *dataItr = data.data(), *dataEnd = data.data() + data.size();
		user_ext_data &usr = user_ext.at(id);

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

				if (mode == CENTER)
				{
					switch (usr.current_stage)
					{
						case user_ext_data::LOGIN_NAME:
						{
							trim(msg);
							usr.name = std::move(msg);
							usr.current_stage = user_ext_data::LOGIN_PASS;
							
							std::string msg_send(msg_input_pass);
							insLen(msg_send);
							msg_send.insert(0, 1, pac_type_msg);
							srv->send_data(id, msg_send, session::priority_msg);
							break;
						}
						case user_ext_data::LOGIN_PASS:
						{
							usr.current_stage = user_ext_data::LOGIN_NAME;
							user_log_list::iterator itr = user_logs.find(usr.name);
							if (itr != user_logs.end())
							{
								trim(msg);
								std::string tmp;
								calcSHA256(msg, tmp);
								if (itr->second.passwd == tmp)
								{
									broadcast_msg(-1, msg_new_user + usr.name + '(' + usr.addr + ')');

									std::string msg_send(msg_welcome);
									insLen(msg_send);
									msg_send.insert(0, 1, pac_type_msg);
									srv->send_data(id, msg_send, session::priority_msg);

									usr.current_stage = user_ext_data::LOGGED_IN;
								}
							}

							if (usr.current_stage == user_ext_data::LOGIN_NAME)
							{
								std::string msg_send(msg_input_name);
								insLen(msg_send);
								msg_send.insert(0, 1, pac_type_msg);
								srv->send_data(id, msg_send, session::priority_msg);
							}
							break;
						}
						case user_ext_data::LOGGED_IN:
						{
							std::string tmp(msg);
							trim(tmp);
							if (tmp.front() == '/')
							{
								tmp.erase(0, 1);
								process_command(tmp, user_logs[usr.name].group);
							}
							else
								broadcast_msg(id, msg);

							break;
						}
					}
				}
				else
					broadcast_msg(id, msg);

				break;
			}
			default:
			{
				if (mode != CENTER || usr.current_stage == user_ext_data::LOGGED_IN)
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

void cli_server_interface::on_join(id_type id)
{
	user_ext_data &ext = user_ext.emplace(id, user_ext_data()).first->second;
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

void cli_server_interface::on_leave(id_type id)
{
	user_ext_list::iterator itr = user_ext.find(id);
	std::string msg_send(msg_del_user);
	if (mode == CENTER)
		msg_send.append(itr->second.name + '(' + itr->second.addr + ')');
	else
		msg_send.append(itr->second.addr);
	user_ext.erase(itr);
	broadcast_msg(-1, msg_send);
}

void cli_server_interface::broadcast_msg(id_type src, const std::string &msg)
{
	std::string msg_send;
	user_ext_data &usr = user_ext[src];
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

void cli_server_interface::broadcast_data(id_type src, const std::string &data, int priority)
{
	std::for_each(user_ext.begin(), user_ext.end(), [src, &data, priority](const std::pair<int, user_ext_data> &p) {
		id_type target = p.first;
		if (target != src && (mode != CENTER || p.second.current_stage == user_ext_data::LOGGED_IN))
		{
			misc_io_service.post([target, data, priority]() {
				srv->send_data(target, data, priority);
			});
		}
	});
}

void cli_server_interface::process_command(std::string cmd, user_log::group_type group)
{
	std::string section;
	while (!(cmd.empty() || isspace(cmd.front())))
	{
		section.push_back(cmd.front());
		cmd.erase(0, 1);
	}
	cmd.erase(0, 1);
	if (section == "op")
	{
		if (group == user_log::ADMIN)
		{
			user_log_list::iterator itr = user_logs.find(cmd);
			if (itr != user_logs.end())
				itr->second.group = user_log::ADMIN;
			main_io_service.post([this]() {
				write_config();
			});
		}
	}
	else if (section == "reg")
	{
		if (group == user_log::ADMIN)
		{
			section.clear();
			while (!(cmd.empty() || isspace(cmd.front())))
			{
				section.push_back(cmd.front());
				cmd.erase(0, 1);
			}
			cmd.erase(0, 1);
			std::string hashed_passwd;
			calcSHA256(cmd, hashed_passwd);

			user_log_list::iterator itr = user_logs.find(section);
			if (itr == user_logs.end())
			{
				user_logs.emplace(section, user_log(section, hashed_passwd, user_log::USER));
				main_io_service.post([this]() {
					write_config();
				});
			}
		}
	}
	else if (section == "unreg")
	{
		if (group == user_log::ADMIN)
		{
			user_log_list::iterator itr = user_logs.find(cmd);
			if (itr != user_logs.end())
			{
				user_logs.erase(itr);
				main_io_service.post([this]() {
					write_config();
				});
			}
		}
	}
	else if (section == "con")
	{
		if (group == user_log::ADMIN)
		{
			srv->connect(cmd);
		}
	}
	else if (section == "stop")
	{
		if (group == user_log::ADMIN)
		{
			server_on = false;
		}
	}
}

void print_usage()
{
	std::cout << "Usage:" << std::endl;
	std::cout << "\tmessenger_server [mode=relay|center]" << std::endl;
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
			else
			{
				print_usage();
				return 0;
			}
		}
		std::srand(static_cast<unsigned int>(std::time(NULL)));

		read_config();

		std::shared_ptr<net::io_service::work> main_iosrv_work = std::make_shared<net::io_service::work>(main_io_service);
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

		std::shared_ptr<net::io_service::work> misc_iosrv_work = std::make_shared<net::io_service::work>(misc_io_service);
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

		user_ext[-1].name = user_ext[-1].addr = "Server";
		srv = new server(main_io_service, misc_io_service, &inter, net::ip::tcp::endpoint(net::ip::tcp::v4(), portListener));
		std::string command;
		while (server_on)
		{
			std::getline(std::cin, command);
			inter.process_command(command, user_log::ADMIN);
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
