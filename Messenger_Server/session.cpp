#include "stdafx.h"
#include "crypto.h"
#include "main.h"

const int portListener = 4826;
using boost::system::error_code;

extern std::list<int> ports;
std::string e0str;

void pre_session::start()
{
	boost::shared_ptr<net::ip::tcp::socket> socket(new net::ip::tcp::socket(io_service));
	acceptor.async_accept(*socket, boost::bind(&pre_session::stage2, this, socket, _1));
}

void pre_session::stage2(boost::shared_ptr<net::ip::tcp::socket> socket, error_code ec)
{
	
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
	boost::asio::async_read(socket,
		boost::asio::buffer(read_msg, msg_size),
		boost::asio::transfer_at_least(1),
		[this, self](boost::system::error_code ec, std::size_t length)
	{
		if (!ec)
		{

			//read_body();
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
	boost::asio::async_read(socket,
		boost::asio::buffer(read_msg, msg_size),
		boost::asio::transfer_at_least(4),
		[this, self](boost::system::error_code ec, std::size_t length)
	{
		if (!ec)
		{
			srv->send(shared_from_this(), std::string(read_msg, length));
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
	boost::asio::async_write(socket,
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
