#include "stdafx.h"
#include "global.h"
#include "crypto.h"
#include "session.h"
#include "main.h"

net::io_service main_io_service, misc_io_service;
cli_server_interface *inter;

user_list users;

iosrv_thread main_io_thread(main_io_service), misc_io_thread(misc_io_service);

modes mode = CENTER;

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
		user &usr = users.at(id);

		byte type;
		checkErr(1);
		type = *dataItr;
		dataItr += 1;
		switch (type)
		{
			case 1:
			{
				data_length_type sizeRecv;
				read_uint(sizeRecv);

				checkErr(sizeRecv);
				std::string msg_utf8(dataItr, sizeRecv);
				dataItr += sizeRecv;

				

				break;
			}
			default:
			{
				
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
	
}

void cli_server_interface::on_leave(id_type id)
{
	
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

		server server(main_io_service, misc_io_service, inter, net::ip::tcp::endpoint(net::ip::tcp::v4(), portListener));
		std::string command;
		while (true)
		{
			std::getline(std::cin, command);
			inter->process_command(command, user::ADMIN);
		}
#ifdef NDEBUG
	}
	catch (std::exception& e)
	{
		std::cerr << "Exception: " << e.what() << "\n";
	}
#endif
	return 0;
}
