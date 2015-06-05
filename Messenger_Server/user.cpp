#include "stdafx.h"
#include "crypto.h"
#include "main.h"

const int portListener = 4826;
using boost::system::error_code;

extern std::list<int> ports;
std::string e0str;

void user::start()
{
	stage2();
}

void user::send(const std::string& msg)
{
	bool write_in_progress = !write_msgs.empty();
	write_msgs.push_back(msg);
	if (!write_in_progress)
	{
		write();
	}
}

void user::stage2()
{
	auto self(shared_from_this());
	boost::asio::async_read(socket,
		boost::asio::buffer(read_msg, msg_size),
		[this, self](boost::system::error_code ec, std::size_t length)
	{
		if (!ec)
		{

		}
	});
}

void user::read_header()
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

void user::read_message_header()
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

void user::read_file_header()
{

}

void user::read_fileblock_header()
{

}

void user::read_message(size_t size)
{

}

void user::read_fileblock()
{

}

void user::write()
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
