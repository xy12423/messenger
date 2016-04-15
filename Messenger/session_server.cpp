#include "stdafx.h"
#include "crypto.h"
#include "session.h"

using namespace msgr_proto;

void insLen(std::string& data)
{
	data_length_type len = boost::endian::native_to_little(static_cast<data_length_type>(data.size()));
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
			std::shared_ptr<pre_session_s> pre_session_s_ptr(std::make_shared<pre_session_s>(port_null, socket, *this, main_io_service, misc_io_service));
			pre_sessions.emplace(pre_session_s_ptr);
		}

		start();
	});
}

void server::pre_session_over(const std::shared_ptr<pre_session>& _pre, bool successful)
{
	if (!successful)
	{
		if (_pre->get_port() != port_null)
			inter.free_rand_port(static_cast<port_type>(_pre->get_port()));
		connectedKeys.erase(_pre->get_key());
	}
	pre_sessions.erase(_pre);
}

void server::join(const session_ptr& _user)
{
	user_id_type newID = nextID;
	nextID++;
	sessions.emplace(newID, _user);
	_user->uid = newID;

	try{ inter.on_join(newID, _user->get_key()); }
	catch (std::exception &ex) { std::cerr << ex.what() << std::endl; }
	catch (...) {}
}

void server::leave(user_id_type _user)
{
	session_list_type::iterator itr(sessions.find(_user));
	if (itr == sessions.end())
		return;
	session_ptr this_session = itr->second;

	try { inter.on_leave(_user); }
	catch (std::exception &ex) { std::cerr << ex.what() << std::endl; }
	catch (...) {}

	this_session->shutdown();
	if (this_session->get_port() != port_null)
		inter.free_rand_port(static_cast<port_type>(this_session->get_port()));
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

bool server::send_data(user_id_type id, const std::string& data, int priority, session::write_callback&& callback)
{
	session_list_type::iterator itr(sessions.find(id));
	if (itr == sessions.end())
		return false;
	session_ptr sptr = itr->second;
	sptr->send(data, priority, std::move(callback));
	return true;
}

bool server::send_data(user_id_type id, std::string&& data, int priority)
{
	return send_data(id, std::move(data), priority, []() {});
}

bool server::send_data(user_id_type id, std::string&& data, int priority, const std::string& message)
{
	return send_data(id, std::move(data), priority, [message]() {std::cout << message << std::endl; });
}

bool server::send_data(user_id_type id, std::string&& data, int priority, session::write_callback&& callback)
{
	session_list_type::iterator itr(sessions.find(id));
	if (itr == sessions.end())
		return false;
	session_ptr sptr = itr->second;
	sptr->send(std::move(data), priority, std::move(callback));
	return true;
}

void server::connect(const std::string& addr_str, port_type remote_port)
{
	connect({ addr_str, std::to_string(remote_port) });
}

void server::connect(unsigned long addr_ulong, port_type remote_port)
{
	connect(asio::ip::tcp::endpoint(asio::ip::address_v4(addr_ulong), remote_port));
}

void server::connect(const asio::ip::tcp::endpoint& remote_endpoint)
{
	port_type local_port;
	if (!inter.new_rand_port(local_port))
		std::cerr << "Socket:No port available" << std::endl;
	else
	{
		socket_ptr socket = std::make_shared<asio::ip::tcp::socket>(main_io_service);

		asio::ip::tcp::endpoint::protocol_type ip_protocol = remote_endpoint.protocol();
		socket->open(ip_protocol);
		socket->bind(asio::ip::tcp::endpoint(ip_protocol, local_port));
		socket->async_connect(remote_endpoint,
			[this, local_port, socket](boost::system::error_code ec)
		{
			if (!ec)
			{
				std::shared_ptr<pre_session_c> pre_session_c_ptr(std::make_shared<pre_session_c>(local_port, socket, *this, main_io_service, misc_io_service));
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

void server::connect(const asio::ip::tcp::resolver::query& query)
{
	port_type local_port;
	if (!inter.new_rand_port(local_port))
		std::cerr << "Socket:No port available" << std::endl;
	else
	{
		resolver.async_resolve(query,
			[this, local_port](const boost::system::error_code& ec, asio::ip::tcp::resolver::iterator itr)
		{
			if (ec)
			{
				std::cerr << "Socket Error:" << ec.message() << std::endl;
				inter.free_rand_port(local_port);
				return;
			}
			socket_ptr socket = std::make_shared<asio::ip::tcp::socket>(main_io_service);

			asio::async_connect(*socket, itr, asio::ip::tcp::resolver::iterator(),
				[this, local_port, socket](const boost::system::error_code& ec, asio::ip::tcp::resolver::iterator next)->asio::ip::tcp::resolver::iterator
			{
				asio::ip::tcp::endpoint::protocol_type ip_protocol = next->endpoint().protocol();
				socket->close();
				socket->open(ip_protocol);
				socket->bind(asio::ip::tcp::endpoint(ip_protocol, local_port));
				return next;
			},
				[this, local_port, socket](boost::system::error_code ec, asio::ip::tcp::resolver::iterator itr)
			{
				if (!ec)
				{
					std::shared_ptr<pre_session_c> pre_session_c_ptr(std::make_shared<pre_session_c>(local_port, socket, *this, main_io_service, misc_io_service));
					pre_sessions.emplace(pre_session_c_ptr);
				}
				else
				{
					std::cerr << "Socket Error:" << ec.message() << std::endl;
					inter.free_rand_port(local_port);
				}
			});
		});
	}
}

void server::disconnect(user_id_type id)
{
	leave(id);
}
