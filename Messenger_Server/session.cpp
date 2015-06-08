#include "stdafx.h"
#include "crypto.h"
#include "main.h"
#include "utils.h"

const int portListener = 4826;
using boost::system::error_code;

extern std::list<int> ports;
std::string e0str;

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

			newUser->start();
			srv->join(newUser);
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
	bool write_in_progress = !write_msgs.empty();
	std::string write_msg;
	encrypt(msg, write_msg, e1);
	insLen(write_msg);
	write_msg.insert(0, "\x01");
	write_msgs.push_back(write_msg);
	if (!write_in_progress)
	{
		write();
	}
}

void session::send_fileheader(const std::string& data)
{
	bool write_in_progress = !write_msgs.empty();
	std::string write_msg(data);
	write_msg.insert(0, "\x02");
	write_msgs.push_back(write_msg);
	if (!write_in_progress)
	{
		write();
	}
}

void session::send_fileblock(const std::string& block)
{
	bool write_in_progress = !write_msgs.empty();
	std::string write_msg;
	encrypt(block, write_msg, e1);
	insLen(write_msg);
	write_msg.insert(0, "\x03");
	write_msgs.push_back(write_msg);
	if (!write_in_progress)
	{
		write();
	}
}

void session::read_header()
{
	boost::asio::async_read(*socket,
		boost::asio::buffer(read_msg_buffer, 1),
		boost::asio::transfer_at_least(1),
		[this](boost::system::error_code ec, std::size_t length)
	{
		if (!ec)
		{
			switch (read_msg_buffer[0])
			{
				case 1:
					read_message_header();
					break;
				case 2:
					read_fileheader_header();
					break;
				case 3:
					read_fileblock_header();
					break;
				default:
					start();
			}
		}
		else
		{
			srv->leave(shared_from_this());
		}
	});
}

void session::read_message_header()
{
	auto self(shared_from_this());
	boost::asio::async_read(*socket,
		boost::asio::buffer(read_msg_buffer, sizeof(unsigned int)),
		boost::asio::transfer_at_least(sizeof(unsigned int)),
		[this, self](boost::system::error_code ec, std::size_t length)
	{
		if (!ec)
		{
			unsigned int sizeRecv = *(reinterpret_cast<unsigned int*>(read_msg_buffer));
			read_message(sizeRecv, new std::string());
		}
		else
		{
			srv->leave(shared_from_this());
		}
	});
}

void session::read_fileheader_header()
{
	auto self(shared_from_this());
	boost::asio::async_read(*socket,
		boost::asio::buffer(read_msg_buffer, sizeof(unsigned int) * 2),
		boost::asio::transfer_at_least(sizeof(unsigned int) * 2),
		[this, self](boost::system::error_code ec, std::size_t length)
	{
		if (!ec)
		{
			std::string *read_msg = new std::string(read_msg_buffer, length);
			unsigned int sizeName = *(reinterpret_cast<unsigned int*>(read_msg_buffer + sizeof(unsigned int)));
			read_fileheader(sizeName, read_msg);
		}
		else
		{
			srv->leave(shared_from_this());
		}
	});
}

void session::read_fileblock_header()
{
	auto self(shared_from_this());
	boost::asio::async_read(*socket,
		boost::asio::buffer(read_msg_buffer, sizeof(unsigned int)),
		boost::asio::transfer_at_least(sizeof(unsigned int)),
		[this, self](boost::system::error_code ec, std::size_t length)
	{
		if (!ec)
		{
			unsigned int sizeRecv = *(reinterpret_cast<unsigned int*>(read_msg_buffer));
			read_fileblock(sizeRecv, new std::string());
		}
		else
		{
			srv->leave(shared_from_this());
		}
	});
}

void session::read_message(size_t size, std::string *read_msg)
{
	try
	{
		if (size > msg_buffer_size)
		{
			boost::asio::async_read(*socket,
				boost::asio::buffer(read_msg_buffer, msg_buffer_size),
				boost::asio::transfer_at_least(msg_buffer_size),
				[this, size, read_msg](boost::system::error_code ec, std::size_t length)
			{
				if (!ec)
				{
					read_msg->append(read_msg_buffer, length);
					read_message(size - length, read_msg);
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
				boost::asio::buffer(read_msg_buffer, size),
				boost::asio::transfer_at_least(size),
				[this, read_msg](boost::system::error_code ec, std::size_t length)
			{
				if (!ec)
				{
					read_msg->append(read_msg_buffer, length);
					std::string msg;
					decrypt(*read_msg, msg);
					delete read_msg;
					//process_message(msg);
					srv->send_message(shared_from_this(), msg);
					start();
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
		delete read_msg;
		start();
	}
}

void session::read_fileheader(size_t size, std::string *read_msg)
{
	try
	{
		if (size > msg_buffer_size)
		{
			boost::asio::async_read(*socket,
				boost::asio::buffer(read_msg_buffer, msg_buffer_size),
				boost::asio::transfer_at_least(msg_buffer_size),
				[this, size, read_msg](boost::system::error_code ec, std::size_t length)
			{
				if (!ec)
				{
					read_msg->append(read_msg_buffer, length);
					read_fileheader(size - length, read_msg);
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
				boost::asio::buffer(read_msg_buffer, size),
				boost::asio::transfer_at_least(size),
				[this, read_msg](boost::system::error_code ec, std::size_t length)
			{
				if (!ec)
				{
					read_msg->append(read_msg_buffer, length);
					srv->send_fileheader(shared_from_this(), *read_msg);
					delete read_msg;
					start();
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
		delete read_msg;
		start();
	}
}

void session::read_fileblock(size_t size, std::string *read_msg)
{
	try
	{
		if (size > msg_buffer_size)
		{
			boost::asio::async_read(*socket,
				boost::asio::buffer(read_msg_buffer, msg_buffer_size),
				boost::asio::transfer_at_least(msg_buffer_size),
				[this, size, read_msg](boost::system::error_code ec, std::size_t length)
			{
				if (!ec)
				{
					read_msg->append(read_msg_buffer, length);
					read_fileblock(size - length, read_msg);
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
				boost::asio::buffer(read_msg_buffer, size),
				boost::asio::transfer_at_least(size),
				[this, read_msg](boost::system::error_code ec, std::size_t length)
			{
				if (!ec)
				{
					read_msg->append(read_msg_buffer, length);
					std::string msg;
					decrypt(*read_msg, msg);
					srv->send_fileblock(shared_from_this(), msg);
					start();
				}
				else
				{
					srv->leave(shared_from_this());
				}
				delete read_msg;
			});
		}
	}
	catch (std::runtime_error ex)
	{
		std::cerr << ex.what() << std::endl;
		delete read_msg;
		start();
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

void session::process_message(const std::string &originMsg)
{
	std::string msg(originMsg);
	ltrim(msg);
	if (msg.front() != '/')
		srv->send_message(shared_from_this(), originMsg);
	else
	{
		msg.erase(0, 1);
		if (msg == "register")
		{

		}
		else if (msg == "login")
		{

		}
	}
}
