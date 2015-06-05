#include "stdafx.h"
#include "crypto.h"
#include "main.h"

const int portListener = 4826;
using boost::system::error_code;

std::list<int> ports;
std::string e0str;

void user::start()
{
	stage1();
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

void user::stage1()
{
	auto self(shared_from_this());
	boost::asio::async_read(socket,
		boost::asio::buffer(read_msg),
		[this, self](boost::system::error_code ec, std::size_t length)
	{
		if (!ec)
		{

		}
	});
}

void user::stage2()
{
	auto self(shared_from_this());
	boost::asio::async_read(socket,
		boost::asio::buffer(read_msg),
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
		boost::asio::buffer(read_msg),
		boost::asio::transfer_at_least(1),
		[this, self](boost::system::error_code ec, std::size_t length)
	{
		if (!ec)
		{

			//read_body();
		}
		else
		{
			//room_.leave(shared_from_this());
		}
	});
}

void user::read_message_header()
{
	auto self(shared_from_this());
	boost::asio::async_read(socket,
		boost::asio::buffer(read_msg),
		boost::asio::transfer_at_least(4),
		[this, self](boost::system::error_code ec, std::size_t length)
	{
		if (!ec)
		{
			//room_.deliver(read_msg_);
			read_header();
		}
		else
		{
			//room_.leave(shared_from_this());
		}
	});
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
			//room_.leave(shared_from_this());
		}
	});
}

void server::accept()
{
	acceptor.async_accept(socket,
		[this](boost::system::error_code ec)
	{
		if (!ec)
		{
			std::make_shared<user>(this, std::move(socket))->start();
		}

		accept();
	});
}

int main()
{
	try
	{
		boost::asio::io_service io_service;
		server server(io_service, net::ip::tcp::endpoint(net::ip::tcp::v4(), portListener));
		io_service.run();
	}
	catch (std::exception& e)
	{
		std::cerr << "Exception: " << e.what() << "\n";
	}

	return 0;
}
