#include "stdafx.h"
#include "crypto.h"
#include "main.h"
#include "utils.h"

const int portListener = 4826;
using boost::system::error_code;

extern std::list<int> ports;
std::string e0str;

const char username_msg[] = "Login as:";
const char passwd_msg[] = "Password:";
const char welcome_msg[] = "Welcome";

void pre_session::start()
{
	std::shared_ptr<net::ip::tcp::socket> socket(std::make_shared<net::ip::tcp::socket>(io_service));
	acceptor.async_accept(*socket, boost::bind(&pre_session::stage1, this, socket, _1));
}

void pre_session::stage1(std::shared_ptr<net::ip::tcp::socket> _socket, error_code ec)
{
	net::async_write(*_socket,
		net::buffer(e0str),
		[this, _socket](boost::system::error_code ec, std::size_t length)
	{
		if (ec)
		{
			std::cerr << "Socket Error:" << ec.message() << std::endl;
			srv->pre_session_over(shared_from_this());
		}
		else
		{
			socket = _socket;
			read_key_header();
		}
	});
	acceptor.close();
}

void pre_session::read_key_header()
{
	net::async_read(*socket,
		net::buffer(reinterpret_cast<char*>(&(this->key_length)), sizeof(unsigned short) / sizeof(char)),
		net::transfer_at_least(sizeof(unsigned short) / sizeof(char)),
		[this](boost::system::error_code ec, std::size_t length)
	{
		if (ec)
		{
			std::cerr << "Socket Error:" << ec.message() << std::endl;
			srv->pre_session_over(shared_from_this());
		}
		else
			read_key();
	});
}

void pre_session::read_key()
{
	key_buffer = new char[key_length];
	net::async_read(*socket,
		net::buffer(key_buffer, key_length),
		net::transfer_at_least(key_length),
		[this](boost::system::error_code ec, std::size_t length)
	{
		if (ec)
			std::cerr << "Socket Error:" << ec.message() << std::endl;
		else
		{
			std::shared_ptr<session> newUser(std::make_shared<session>(srv, socket));

			session &item = *newUser;
			std::string keyStr(key_buffer, key_length);
			CryptoPP::StringSource keySource(keyStr, true);
			item.e1.AccessPublicKey().Load(keySource);

			if (mode == CENTER)
				newUser->send_message(username_msg);
			else
				srv->send_message(nullptr, "New user " + socket->remote_endpoint().address().to_string());
			srv->join(newUser);
			newUser->start();
		}
		srv->pre_session_over(shared_from_this());
	});
}

void session::start()
{
	read_header();
}

void session::send_message(const std::string& msg)
{
	std::string send_msg(msg);
	insLen(send_msg);
	send_msg.insert(0, "\x01");
	send(send_msg);
}

void session::send(const std::string& data)
{
	if (data.empty())
		return;
	bool write_in_progress = !write_msgs.empty();
	std::string write_msg;
	encrypt(data, write_msg, e1);
	insLen(write_msg);
	write_msgs.push_back(write_msg);
	if (!write_in_progress)
	{
		write();
	}
}

void session::read_header()
{
	boost::asio::async_read(*socket,
		boost::asio::buffer(read_msg_buffer, 4),
		boost::asio::transfer_at_least(4),
		[this](boost::system::error_code ec, std::size_t length)
	{
		if (!ec)
		{
			unsigned int sizeRecv = *(reinterpret_cast<unsigned int*>(read_msg_buffer));
			read_data(sizeRecv, std::make_shared<std::string>());
		}
		else
		{
			srv->leave(shared_from_this());
		}
	});
}

void session::read_data(size_t sizeLast, std::shared_ptr<std::string> buf)
{
	try
	{
		if (sizeLast > msg_buffer_size)
		{
			boost::asio::async_read(*socket,
				boost::asio::buffer(read_msg_buffer, msg_buffer_size),
				boost::asio::transfer_at_least(msg_buffer_size),
				[this, sizeLast, buf](boost::system::error_code ec, std::size_t length)
			{
				if (!ec)
				{
					buf->append(read_msg_buffer, length);
					read_data(sizeLast - length, buf);
				}
				else
				{
					srv->leave(shared_from_this());
				}
			});
		}
		else
		{
			boost::asio::async_read(*socket,
				boost::asio::buffer(read_msg_buffer, sizeLast),
				boost::asio::transfer_at_least(sizeLast),
				[this, buf](boost::system::error_code ec, std::size_t length)
			{
				if (!ec)
				{
					buf->append(read_msg_buffer, length);
					std::string msg;
					decrypt(*buf, msg);
					process_data(msg);
				}
				else
				{
					srv->leave(shared_from_this());
				}
			});
		}
	}
	catch (std::runtime_error ex)
	{
		std::cerr << ex.what() << std::endl;
		srv->leave(shared_from_this());
	}
}

#define checkErr if (in.fail()) throw(0)

void session::process_data(const std::string &data)
{
	char *buf = NULL;
	try
	{
		std::stringstream in;
		in.write(data.data(), data.size());

		byte type;
		in.read(reinterpret_cast<char*>(&type), sizeof(byte));
		switch (type)
		{
			case 0:
				break;
			case 1:
			{
				unsigned int sizeRecv;
				in.read(reinterpret_cast<char*>(&sizeRecv), sizeof(unsigned int) / sizeof(char));
				checkErr;

				buf = new char[sizeRecv];
				in.read(buf, sizeRecv);
				std::string str(buf, sizeRecv);
				delete[] buf;
				buf = NULL;

				if (mode == CENTER)
					process_message(str);
				else
					srv->send_message(shared_from_this(), str);

				break;
			}
			default:
			{
				if (mode == RELAY)
					srv->send(shared_from_this(), std::string(data.data() + 1, data.size() - 1));
			}
		}
	}
	catch (std::exception ex)
	{
		std::cout << ex.what() << "\n";
	}
	catch (...)
	{
	}
	try
	{
		if (buf != NULL)
			delete[] buf;
	}
	catch (...)
	{
	}
	start();
}

void session::process_message(const std::string &origin_msg)
{
	switch (state)
	{
		case INPUT_USER:
		{
			user_name = origin_msg;
			trim(user_name);
			send_message(passwd_msg);
			state = INPUT_PASSWD;
			break;
		}
		case INPUT_PASSWD:
		{
			bool success = srv->login(user_name, origin_msg);
			if (success)
			{
				srv->send_message(nullptr, "New user " + get_address());
				state = LOGGED_IN;
				send_message(welcome_msg);
			}
			else
			{
				state = INPUT_USER;
				send_message(username_msg);
			}
			break;
		}
		case LOGGED_IN:
		{
			std::string msg(origin_msg);
			ltrim(msg);
			if (msg.front() != '/')
				srv->send_message(shared_from_this(), origin_msg);
			else
			{
				msg.erase(0, 1);
				srv->process_command(msg, srv->get_group(user_name));
			}
			break;
		}
	}
}

void session::write()
{
	boost::asio::async_write(*socket,
		boost::asio::buffer(write_msgs.front()),
		[this](boost::system::error_code ec, std::size_t /*length*/)
	{
		if (!ec)
		{
			write_msgs.pop_front();
			if (!write_msgs.empty())
			{
				write();
			}
		}
		else
		{
			srv->leave(shared_from_this());
		}
	});
}
