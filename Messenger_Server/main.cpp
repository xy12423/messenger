#include "stdafx.h"
#include "crypto.h"
#include "main.h"

const int portListener = 4826;
using boost::system::error_code;

std::list<int> ports;
extern std::string e0str;

void server::start()
{
	boost::shared_ptr<net::ip::tcp::socket> socket(new net::ip::tcp::socket(io_service));
	acceptor.async_accept(*socket, boost::bind(&server::accept, this, socket, _1));
}

void server::accept(boost::shared_ptr<net::ip::tcp::socket> socket, error_code ec)
{
	if (!ec)
	{
		
		std::shared_ptr<pre_session> ptr = std::make_shared<pre_session>(this, std::move(socket));
		pre_sessions.emplace(ptr);
		ptr->start();
	}

	start();
}

void server::stage1()
{/*
	acceptor.async_accept(socket,
		[this](boost::system::error_code ec)
	{
		if (!ec)
		{
			std::make_shared<pre_session>(this, std::move(socket))->start();
		}

		accept();
	});*/
}

void server::send(std::shared_ptr<session> from, const std::string& msg)
{
	userList::iterator itr = users.begin(), itrEnd = users.end();
	for (; itr != itrEnd; itr++)
		if (*itr != from)
		(*itr)->send(msg);
}

void server::leave(std::shared_ptr<session> _user)
{
	users.erase(_user);
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
