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

void server::start()
{
	if (closing)
		return;
	socket_ptr socket = std::make_shared<asio::ip::tcp::socket>(main_io_service);
	acceptor.async_accept(*socket,
		[this, socket](boost::system::error_code ec) {
		if (closing)
			return;
		if (!ec)
		{
			std::shared_ptr<pre_session_s> pre_session_s_ptr(std::make_shared<pre_session_s>(port_null, socket, this, main_io_service, misc_io_service));
			pre_sessions.emplace(pre_session_s_ptr);
		}

		start();
	}
	);
}

void server::pre_session_over(std::shared_ptr<pre_session> _pre, bool successful)
{
	if (!successful)
	{
		if (_pre->get_port() != port_null)
			inter.free_rand_port(_pre->get_port());
		connectedKeys.erase(_pre->get_key());
	}
	pre_sessions.erase(_pre);
}

void server::join(const session_ptr &_user)
{
	user_id_type newID = nextID;
	nextID++;
	sessions.emplace(newID, _user);

	try{ inter.on_join(newID); }
	catch (std::exception &ex) { std::cerr << ex.what() << std::endl; }
	catch (...) {}

	_user->uid = newID;
}

void server::leave(user_id_type _user)
{
	session_list_type::iterator itr(sessions.find(_user));
	if (itr == sessions.end())
		return;
	session_ptr this_session = itr->second;
	this_session->shutdown();

	try { inter.on_leave(_user); }
	catch (std::exception &ex) { std::cerr << ex.what() << std::endl; }
	catch (...) {}

	if (this_session->get_port() != port_null)
		inter.free_rand_port(this_session->get_port());
	connectedKeys.erase(this_session->get_key());
	sessions.erase(itr);
}

void server::on_data(user_id_type id, std::shared_ptr<std::string> data)
{
	session_ptr this_session = sessions[id];
	misc_io_service.post([this, id, data, this_session]() {
		try { inter.on_data(id, *data); }
		catch (std::exception &ex) { std::cerr << ex.what() << std::endl; }
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
	session_list_type::iterator itr(sessions.find(id));
	if (itr == sessions.end())
		return false;
	session_ptr sptr = itr->second;
	sptr->send(data, priority, std::move(callback));
	return true;
}

void server::connect(const std::string &addr_str, port_type remote_port)
{
	connect({ addr_str, std::to_string(remote_port) });
}

void server::connect(unsigned long addr_ulong, port_type remote_port)
{
	connect(asio::ip::tcp::endpoint(asio::ip::address_v4(addr_ulong), remote_port));
}

void server::connect(const asio::ip::tcp::endpoint &remote_endpoint)
{
	port_type local_port;
	if (!inter.new_rand_port(local_port))
		std::cerr << "Socket:No port available" << std::endl;
	else
	{
		socket_ptr socket = std::make_shared<asio::ip::tcp::socket>(main_io_service);

		socket->open(asio::ip::tcp::v4());
		socket->bind(asio::ip::tcp::endpoint(asio::ip::tcp::v4(), local_port));
		socket->async_connect(remote_endpoint,
			[this, local_port, socket](boost::system::error_code ec)
		{
			if (!ec)
			{
				std::shared_ptr<pre_session_c> pre_session_c_ptr(std::make_shared<pre_session_c>(local_port, socket, this, main_io_service, misc_io_service));
				pre_sessions.emplace(pre_session_c_ptr);
			}
			else
			{
				std::cerr << "Socket Error:" << ec.message() << std::endl;
				inter.free_rand_port(local_port);
			}
		});
	}
}

void server::connect(const asio::ip::tcp::resolver::query &query)
{
	port_type local_port;
	if (!inter.new_rand_port(local_port))
		std::cerr << "Socket:No port available" << std::endl;
	else
	{
		resolver.async_resolve(query,
			[this, local_port](const boost::system::error_code& ec, asio::ip::tcp::resolver::iterator itr)
		{
			socket_ptr socket = std::make_shared<asio::ip::tcp::socket>(main_io_service);

			socket->open(asio::ip::tcp::v4());
			socket->bind(asio::ip::tcp::endpoint(asio::ip::tcp::v4(), local_port));
			asio::async_connect(*socket, itr, asio::ip::tcp::resolver::iterator(),
				[this, local_port, socket](boost::system::error_code ec, asio::ip::tcp::resolver::iterator itr)
			{
				if (itr == asio::ip::tcp::resolver::iterator())
				{
					std::cerr << "Can't connect to host" << std::endl;
					inter.free_rand_port(local_port);
				}
				else if (ec)
				{
					std::cerr << "Socket Error:" << ec.message() << std::endl;
					inter.free_rand_port(local_port);
				}
				else
				{
					std::shared_ptr<pre_session_c> pre_session_c_ptr(std::make_shared<pre_session_c>(local_port, socket, this, main_io_service, misc_io_service));
					pre_sessions.emplace(pre_session_c_ptr);
				}
			});
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
