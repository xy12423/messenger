#include "stdafx.h"
#include "crypto.h"
#include "main.h"

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
			srv->join(newUser);
		}
		srv->pre_session_over(shared_from_this());
	});
}

void session::start()
{
	read_header();
}

void session::send(const std::string& msg)
{
	bool write_in_progress = !write_msgs.empty();
	write_msgs.push_back(msg);
	if (!write_in_progress)
	{
		write();
	}
}

void session::read_header()
{
	auto self(shared_from_this());
	boost::asio::async_read(*socket,
		boost::asio::buffer(read_msg_buffer, 1),
		boost::asio::transfer_at_least(1),
		[this, self](boost::system::error_code ec, std::size_t length)
	{
		if (!ec)
		{

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
		boost::asio::buffer(read_msg_buffer, msg_buffer_size),
		boost::asio::transfer_at_least(4),
		[this, self](boost::system::error_code ec, std::size_t length)
	{
		if (!ec)
		{
			srv->send(shared_from_this(), std::string(read_msg_buffer, length));
			read_header();
		}
		else
		{
			srv->leave(shared_from_this());
		}
	});
}

void session::read_file_header()
{

}

void session::read_fileblock_header()
{

}

void session::read_message(size_t size)
{

}

void session::read_fileblock()
{

}

void session::write()
{
	auto self(shared_from_this());
	boost::asio::async_write(*socket,
		boost::asio::buffer(write_msgs.front()),
		[this, self](boost::system::error_code ec, std::size_t /*length*/)
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
