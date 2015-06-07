#include "stdafx.h"
#include "crypto.h"
#include "main.h"

const int portListener = 4826;
using boost::system::error_code;

std::list<int> ports;
extern std::string e0str;

int newPort()
{
	if (ports.empty())
		return -1;
	std::list<int>::iterator portItr = ports.begin();
	for (int i = std::rand() % ports.size(); i > 0; i--)
		portItr++;
	int port = *portItr;
	ports.erase(portItr);
	return port;
}

void freePort(unsigned short port)
{
	ports.push_back(port);
}

void server::start()
{
	accepting = std::make_shared<net::ip::tcp::socket>(io_service);
	acceptor.async_accept(*accepting,
		[this](boost::system::error_code ec){
		accept(ec);
	}
	);
}

void server::accept(error_code ec)
{
	if (!ec)
	{
		int port = newPort();
		if (port == -1)
			std::cerr << "Socket:No port available" << std::endl;
		else
		{
			net::ip::tcp::endpoint localAddr(net::ip::tcp::v4(), port);
			pre_sessions.emplace(std::make_shared<pre_session>(io_service, localAddr, this));

			socket_ptr accepted(accepting);
			unsigned short port_send = static_cast<unsigned short>(port);
			const int send_size = sizeof(unsigned short) / sizeof(char);
			char* send_buf = new char[send_size];
			memcpy(send_buf, reinterpret_cast<char*>(&port_send), send_size);
			net::async_write(*accepted,
				net::buffer(send_buf, send_size),
				[accepted, send_buf](boost::system::error_code ec, std::size_t length)
			{
				delete[] send_buf;
				accepted->close();
			}
			);
		}
	}

	start();
}

void server::send_message(std::shared_ptr<session> from, const std::string& msg)
{
	userList::iterator itr = users.begin(), itrEnd = users.end();
	for (; itr != itrEnd; itr++)
		if (*itr != from)
			(*itr)->send_message(msg);
}

void server::send_fileheader(std::shared_ptr<session> from, const std::string& data)
{
	userList::iterator itr = users.begin(), itrEnd = users.end();
	for (; itr != itrEnd; itr++)
		if (*itr != from)
			(*itr)->send_fileheader(data);
}

void server::send_fileblock(std::shared_ptr<session> from, const std::string& block)
{
	userList::iterator itr = users.begin(), itrEnd = users.end();
	for (; itr != itrEnd; itr++)
		if (*itr != from)
			(*itr)->send_fileblock(block);
}

int main()
{
#ifdef NDEBUG
	try
	{
#endif
		boost::asio::io_service io_service;

		for (int i = 5001; i <= 10000; i++)
			ports.push_back(i);
		std::srand(static_cast<unsigned int>(std::time(NULL)));

		e0str = getPublicKey();
		unsigned short e0len = static_cast<unsigned short>(e0str.size());
		e0str = std::string(reinterpret_cast<const char*>(&e0len), sizeof(unsigned short) / sizeof(char)) + e0str;

		server server(io_service, net::ip::tcp::endpoint(net::ip::tcp::v4(), portListener));
		io_service.run();
#ifdef NDEBUG
	}
	catch (std::exception& e)
	{
		std::cerr << "Exception: " << e.what() << "\n";
	}
#endif
	return 0;
}
