#include "stdafx.h"
#include "crypto.h"
#include "session.h"

using boost::system::error_code;

const char* privatekeyFile = ".privatekey";
const char* publickeysFile = ".publickey";

void insLen(std::string &data)
{
	data_length_type len = boost::endian::native_to_little<data_length_type>(static_cast<data_length_type>(data.size()));
	data.insert(0, std::string(reinterpret_cast<const char*>(&len), sizeof(data_length_type)));
}

//This only find a port in ports list without validating
int new_port(std::list<port_type> &ports)
{
	if (ports.empty())
		return -1;
	std::list<port_type>::iterator portItr = ports.begin();
	for (int i = std::rand() % ports.size(); i > 0; i--)
		portItr++;
	int port = *portItr;
	ports.erase(portItr);
	return port;
}

//This only insert port to ports list without really free socket
void free_port(std::list<port_type> &ports, port_type port)
{
	ports.push_back(port);
}

void server::start()
{
	if (closing)
		return;
	accepting = std::make_shared<net::ip::tcp::socket>(main_io_service);
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
		int port = new_port(local_ports);
		if (port == -1)
			std::cerr << "Socket:No port available" << std::endl;
		else
		{
			net::ip::tcp::endpoint localAddr(net::ip::tcp::v4(), port);
			std::shared_ptr<pre_session_s> pre_session_s_ptr(std::make_shared<pre_session_s>(port, localAddr, this, main_io_service, misc_io_service));
			pre_session_s_ptr->start();
			pre_sessions.emplace(pre_session_s_ptr);

			socket_ptr accepted(accepting);
			port_type port_send = static_cast<port_type>(port);
			const int send_size = sizeof(port_type);
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

void server::pre_session_over(std::shared_ptr<pre_session> _pre, bool successful)
{
	if (!successful)
	{
		free_port(local_ports, _pre->get_port());
		connectedKeys.erase(_pre->get_key());
	}
	pre_sessions.erase(_pre);
}

user_id_type server::join(const session_ptr &_user)
{
	user_id_type newID = nextID;
	nextID++;
	sessions.emplace(newID, _user);

	try{ inter->on_join(newID); }
	catch (std::exception ex) { std::cerr << ex.what() << std::endl; }
	catch (...) {}

	return newID;
}

void server::leave(user_id_type _user)
{
	sessionList::iterator itr(sessions.find(_user));
	if (itr == sessions.end())
		return;
	session_ptr this_session = itr->second;
	this_session->shutdown();

	try { inter->on_leave(_user); }
	catch (std::exception ex) { std::cerr << ex.what() << std::endl; }
	catch (...) {}

	free_port(local_ports, this_session->get_port());
	connectedKeys.erase(this_session->get_key());
	sessions.erase(itr);
}

void server::on_data(user_id_type id, std::shared_ptr<std::string> data)
{
	session_ptr this_session = sessions[id];
	misc_io_service.post([this, id, data, this_session]() {
		std::string decrypted_data;
		decrypt(*data, decrypted_data);
		
		std::string sha256_recv(decrypted_data, 0, sha256_size), sha256_real;
		calcSHA256(decrypted_data, sha256_real, sha256_size);
		if (sha256_real != sha256_recv)
		{
			std::cerr << "Error:Hashing failed" << std::endl;
			leave(id);
			return;
		}

		session_id_type sid = this_session->get_session_id();
		if (*reinterpret_cast<const session_id_type*>(decrypted_data.data() + sha256_size) != boost::endian::little_to_native<session_id_type>(sid))
		{
			std::cerr << "Error:Checking failed" << std::endl;
			leave(id);
			return;
		}
		decrypted_data.erase(0, sizeof(session_id_type) + sha256_size);

		try { inter->on_data(id, decrypted_data); }
		catch (std::exception ex) { std::cerr << ex.what() << std::endl; }
		catch (...) {}
	});
}

bool server::send_data(user_id_type id, const std::string& data, int priority)
{
	return send_data(id, data, priority, []() {});
}

bool server::send_data(user_id_type id, const std::string& data, int priority, const std::string& message)
{
	return send_data(id, data, priority, [message]() {std::cout << message << std::endl; });
}

bool server::send_data(user_id_type id, const std::string& data, int priority, session::write_callback &&callback)
{
	sessionList::iterator itr(sessions.find(id));
	if (itr == sessions.end())
		return false;
	session_ptr sptr = itr->second;
	sptr->send(data, priority, std::move(callback));
	return true;
}

void server::connect(const std::string &addr_str, port_type remote_port)
{
	connect(net::ip::address::from_string(addr_str), remote_port);
}

void server::connect(unsigned long addr_ulong, port_type remote_port)
{
	connect(net::ip::address_v4(addr_ulong), remote_port);
}

void server::connect(const net::ip::address &addr, port_type remote_port)
{
	int local_port = new_port(local_ports);
	if (local_port == -1)
		std::cerr << "Socket:No port available" << std::endl;
	else
	{
		socket_ptr new_socket(std::make_shared<net::ip::tcp::socket>(main_io_service));
		net::ip::tcp::endpoint local_endpoint(net::ip::tcp::v4(), local_port_connect), remote_endpoint(addr, remote_port);

		new_socket->open(net::ip::tcp::v4());
		new_socket->bind(local_endpoint);
		new_socket->async_connect(remote_endpoint, [this, new_socket, addr, local_port](const boost::system::error_code& ec) {
			if (!ec)
			{
				const int port_size = sizeof(port_type);
				char* remote_port_buf = new char[port_size];
				net::async_read(*new_socket,
					net::buffer(remote_port_buf, port_size),
					net::transfer_exactly(port_size),
					[this, new_socket, addr, remote_port_buf, local_port](boost::system::error_code ec, std::size_t length)
				{
					if (!ec)
					{
						port_type remote_port_new = *reinterpret_cast<port_type*>(remote_port_buf);
						remote_port_new = boost::endian::little_to_native<port_type>(remote_port_new);
						net::ip::tcp::endpoint remote_endpoint_new(addr, remote_port_new);
						std::shared_ptr<pre_session_c> pre_session_c_ptr(std::make_shared<pre_session_c>(local_port, remote_endpoint_new, this, main_io_service, misc_io_service));
						pre_session_c_ptr->start();
						pre_sessions.emplace(pre_session_c_ptr);

						new_socket->close();
					}
					else
					{
						std::cerr << "Socket Error:" << ec.message() << std::endl;
						free_port(local_ports, local_port);
					}
					delete[] remote_port_buf;
				});
			}
			else
			{
				std::cerr << "Socket Error:" << ec.message() << std::endl;
				free_port(local_ports, local_port);
			}
		});
	}
}

void server::disconnect(user_id_type id)
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
		size_t pubCount = 0, keyLen = 0;
		std::ifstream publicIn(publickeysFile, std::ios_base::in | std::ios_base::binary);
		publicIn.read(reinterpret_cast<char*>(&pubCount), sizeof(size_t));
		for (; pubCount > 0; pubCount--)
		{
			publicIn.read(reinterpret_cast<char*>(&keyLen), sizeof(size_t));
			std::unique_ptr<char[]> buf = std::make_unique<char[]>(keyLen);
			publicIn.read(buf.get(), keyLen);
			certifiedKeys.emplace(std::string(buf.get(), keyLen));
		}

		publicIn.close();
	}

	e0str = getPublicKey();
	key_length_type e0len = boost::endian::native_to_little<key_length_type>(static_cast<key_length_type>(e0str.size()));
	e0str = std::string(reinterpret_cast<const char*>(&e0len), sizeof(key_length_type)) + e0str;
}

void server::write_data()
{
	size_t pubCount = certifiedKeys.size(), keySize = 0;
	std::ofstream publicOut(publickeysFile, std::ios_base::out | std::ios_base::binary);
	publicOut.write(reinterpret_cast<char*>(&pubCount), sizeof(size_t));

	std::unordered_set<std::string>::iterator itr = certifiedKeys.begin(), itrEnd = certifiedKeys.end();
	for (; itr != itrEnd; itr++)
	{
		keySize = static_cast<size_t>(itr->size());
		publicOut.write(reinterpret_cast<char*>(&keySize), sizeof(size_t));
		publicOut.write(itr->data(), keySize);
	}

	publicOut.close();
}
