#include "stdafx.h"
#include "crypto.h"
#include "session.h"

using boost::system::error_code;

const char* privatekeyFile = ".privatekey";
const char* publickeysFile = ".publickey";

net::io_service io_service;

int newPort(std::list<int> &ports)
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

void freePort(std::list<int> &ports, unsigned short port)
{
	ports.push_back(port);
}

void server::start()
{
	if (closing)
		return;
	accepting = std::make_shared<net::ip::tcp::socket>(io_service);
	acceptor.async_accept(*accepting,
		[this](boost::system::error_code ec) {
		accept(ec);
	}
	);
}

void server::accept(error_code ec)
{
	if (closing)
		return;
	if (!ec)
	{
		int port = newPort(ports);
		if (port == -1)
			std::cerr << "Socket:No port available" << std::endl;
		else
		{
			net::ip::tcp::endpoint localAddr(net::ip::tcp::v4(), port);
			std::shared_ptr<pre_session_s> pre_session_s_ptr(std::make_shared<pre_session_s>(port, localAddr, this, io_service));
			pre_session_s_ptr->start();
			pre_sessions.emplace(pre_session_s_ptr);

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

void server::pre_session_over(std::shared_ptr<pre_session> _pre)
{
	freePort(ports, _pre->get_port());
	pre_sessions.erase(_pre);
}

id_type server::join(const session_ptr &_user)
{
	id_type newID = nextID;
	nextID++;
	sessions.emplace(newID, _user);
	inter->on_join(newID);
	return newID;
}

void server::leave(id_type _user)
{
	sessionList::iterator itr(sessions.find(_user));
	if (itr == sessions.end())
		return;
	inter->on_leave(_user);
	freePort(ports, itr->second->get_port());
	sessions.erase(_user);
}

void server::on_data(id_type id, const std::string& data)
{
	inter->on_data(id, data);
}

bool server::send_data(id_type id, const std::string& data, const std::wstring& message)
{
	sessionList::iterator itr(sessions.find(id));
	if (itr == sessions.end())
		return false;
	session_ptr sptr = itr->second;
	sptr->send(data, message);
	return true;
}

void server::connect(const std::string &addr_str)
{
	int local_port = newPort(ports);
	if (local_port == -1)
		std::cerr << "Socket:No port available" << std::endl;
	else
	{
		socket_ptr new_socket(std::make_shared<net::ip::tcp::socket>(io_service));
		net::ip::address addr(net::ip::address::from_string(addr_str));
		net::ip::tcp::endpoint local_endpoint(net::ip::tcp::v4(), portConnect), remote_endpoint(addr, portListener);

		new_socket->open(net::ip::tcp::v4());
		new_socket->bind(local_endpoint);
		new_socket->async_connect(remote_endpoint, [this, new_socket, addr, local_port](const boost::system::error_code& ec) {
			if (!ec)
			{
				const int port_size = sizeof(unsigned short) / sizeof(char);
				char* remote_port_buf = new char[port_size];
				net::async_read(*new_socket,
					net::buffer(remote_port_buf, port_size),
					net::transfer_at_least(port_size),
					[this, new_socket, addr, remote_port_buf, local_port](boost::system::error_code ec, std::size_t length)
				{
					if (ec)
					{
						std::cerr << "Socket Error:" << ec.message() << std::endl;
						freePort(ports, local_port);
					}
					else
					{
						net::ip::tcp::endpoint remote_endpoint_new(addr, *reinterpret_cast<unsigned short*>(remote_port_buf));
						std::shared_ptr<pre_session_c> pre_session_c_ptr(std::make_shared<pre_session_c>(local_port, remote_endpoint_new, this, io_service));
						pre_session_c_ptr->start();
						pre_sessions.emplace(pre_session_c_ptr);

						new_socket->close();
					}
					delete[] remote_port_buf;
				});
			}
			else
			{
				std::cerr << "Socket Error:" << ec.message() << std::endl;
				freePort(ports, local_port);
			}
		});
	}
}

void server::disconnect(id_type id)
{
	leave(id);
}

void server::read_data()
{
	if (fs::exists(privatekeyFile))
		initKey();
	else
		genKey();

	if (fs::exists(publickeysFile))
	{
		unsigned int pubCount = 0, keyLen = 0;
		std::ifstream publicIn(publickeysFile, std::ios_base::in | std::ios_base::binary);
		publicIn.read(reinterpret_cast<char*>(&pubCount), sizeof(unsigned int) / sizeof(char));
		for (; pubCount > 0; pubCount--)
		{
			publicIn.read(reinterpret_cast<char*>(&keyLen), sizeof(unsigned int) / sizeof(char));
			char *buf = new char[keyLen];
			publicIn.read(buf, keyLen);
			certifiedKeys.emplace(std::string(buf, keyLen));
			delete[] buf;
		}
	}

	e0str = getPublicKey();
	unsigned short e0len = wxUINT16_SWAP_ON_BE(static_cast<unsigned short>(e0str.size()));
	e0str = std::string(reinterpret_cast<const char*>(&e0len), sizeof(unsigned short) / sizeof(char)) + e0str;
}

void server::write_data()
{
	unsigned int pubCount = certifiedKeys.size(), keyLen = 0;
	std::ofstream publicIn(publickeysFile, std::ios_base::out | std::ios_base::binary);
	publicIn.write(reinterpret_cast<char*>(&pubCount), sizeof(unsigned int) / sizeof(char));

	std::unordered_set<std::string>::iterator itr = certifiedKeys.begin(), itrEnd = certifiedKeys.end();
	for (; itr != itrEnd; itr++)
	{
		keyLen = static_cast<unsigned int>(itr->size());
		publicIn.write(reinterpret_cast<char*>(&keyLen), sizeof(unsigned int) / sizeof(char));
		publicIn.write(itr->data(), keyLen);
	}
}
