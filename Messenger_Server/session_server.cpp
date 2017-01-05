#include "stdafx.h"
#include "crypto.h"
#include "session.h"

using namespace msgr_proto;

void insLen(std::string& data)
{
	data_size_type len = boost::endian::native_to_little(static_cast<data_size_type>(data.size()));
	data.insert(0, reinterpret_cast<const char*>(&len), sizeof(data_size_type));
}

void server::do_start()
{
	if (closing)
		return;
	socket_ptr socket = std::make_shared<asio::ip::tcp::socket>(main_io_service);
	acceptor.async_accept(*socket,
		[this, socket](const error_code_type& ec) {
		if (closing)
			return;
		if (!ec)
		{
			std::shared_ptr<pre_session_s> pre_session_s_ptr(std::make_shared<pre_session_s>(port_null, socket, *this, crypto_prov, crypto_srv, main_io_service, misc_io_service));
			std::unique_lock<std::mutex> lock(pre_session_mutex);
			pre_sessions.emplace(pre_session_s_ptr);
			lock.unlock();
			pre_session_s_ptr->start();
		}

		do_start();
	});
}

void server::shutdown()
{
	closing = true;
	std::lock_guard<std::mutex> lock(session_mutex);
	acceptor.close();
	for (std::unordered_set<std::shared_ptr<pre_session>>::iterator itr = pre_sessions.begin(), itr_end = pre_sessions.end(); itr != itr_end; itr = pre_sessions.erase(itr))
		(*itr)->shutdown();
	for (session_list_type::iterator itr = sessions.begin(), itr_end = sessions.end(); itr != itr_end; itr = sessions.erase(itr))
		itr->second->shutdown();
	while (session_active_count != 0);
}

void server::pre_session_over(const std::shared_ptr<pre_session>& _pre, bool successful)
{
	std::lock_guard<std::mutex> lock(pre_session_mutex);
	if (!successful)
	{
		if (_pre->get_port() != port_null)
			free_rand_port(static_cast<port_type>(_pre->get_port()));
		connected_keys.erase(_pre->get_key());
	}
	_pre->shutdown();
	pre_sessions.erase(_pre);
}

void server::join(const session_ptr& _user, user_id_type& uid)
{
	if (closing)
		return;
	std::lock_guard<std::mutex> lock(session_mutex);
	user_id_type newID = nextID;
	nextID++;
	sessions.emplace(newID, _user);
	uid = newID;

	misc_io_service.post([this, newID, _user]() {
		try { on_join(newID, _user->get_key()); }
		catch (std::exception &ex) { on_exception(ex); }
		catch (...) {}
	});
}

void server::leave(user_id_type _user)
{
	if (closing)
		return;
	std::lock_guard<std::mutex> lock(session_mutex);
	session_list_type::iterator itr(sessions.find(_user));
	if (itr == sessions.end())
		return;
	session_ptr this_session = itr->second;

	misc_io_service.post([this, _user]() {
		try { on_leave(_user); }
		catch (std::exception &ex) { on_exception(ex); }
		catch (...) {}
	});

	this_session->shutdown();
	if (this_session->get_port() != port_null)
		free_rand_port(static_cast<port_type>(this_session->get_port()));
	connected_keys.erase(this_session->get_key());
	sessions.erase(itr);
}

void server::on_recv_data(user_id_type id, const std::shared_ptr<std::string>& data)
{
	if (closing)
		return;
	std::lock_guard<std::mutex> lock(session_mutex);
	session_list_type::iterator itr(sessions.find(id));
	if (itr == sessions.end())
		return;
	session_ptr this_session = itr->second;
	misc_io_service.post([this, id, data]() {
		try { on_data(id, *data); }
		catch (std::exception &ex) { on_exception(ex); }
		catch (...) {}
	});
}

bool server::send_data(user_id_type id, const std::string& data, int priority, session::write_callback&& callback)
{
	if (closing)
		return false;
	std::lock_guard<std::mutex> lock(session_mutex);
	session_list_type::iterator itr(sessions.find(id));
	if (itr == sessions.end())
		return false;
	session_ptr sptr = itr->second;
	sptr->send(data, priority, std::move(callback));
	return true;
}

bool server::send_data(user_id_type id, std::string&& data, int priority, session::write_callback&& callback)
{
	if (closing)
		return false;
	std::lock_guard<std::mutex> lock(session_mutex);
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
	if (!new_rand_port(local_port))
		on_exception("Socket:No port available");
	else
	{
		socket_ptr socket = std::make_shared<asio::ip::tcp::socket>(main_io_service);

		asio::ip::tcp::endpoint::protocol_type ip_protocol = remote_endpoint.protocol();
		socket->open(ip_protocol);
		socket->bind(asio::ip::tcp::endpoint(ip_protocol, local_port));
		socket->async_connect(remote_endpoint,
			[this, local_port, socket](const error_code_type& ec)
		{
			if (!ec)
			{
				std::shared_ptr<pre_session_c> pre_session_c_ptr(std::make_shared<pre_session_c>(local_port, socket, *this, crypto_prov, crypto_srv, main_io_service, misc_io_service));
				std::unique_lock<std::mutex> lock(pre_session_mutex);
				pre_sessions.emplace(pre_session_c_ptr);
				lock.unlock();
				pre_session_c_ptr->start();
			}
			else
			{
				on_exception("Socket Error:" + ec.message());
				free_rand_port(local_port);
			}
		});
	}
}

void server::connect(const asio::ip::tcp::resolver::query& query)
{
	port_type local_port;
	if (!new_rand_port(local_port))
		on_exception("Socket:No port available");
	else
	{
		resolver.async_resolve(query,
			[this, local_port](const error_code_type& ec, asio::ip::tcp::resolver::iterator itr)
		{
			if (ec)
			{
				on_exception("Socket Error:" + ec.message());
				free_rand_port(local_port);
				return;
			}
			socket_ptr socket = std::make_shared<asio::ip::tcp::socket>(main_io_service);

			asio::async_connect(*socket, itr, asio::ip::tcp::resolver::iterator(),
				[this, local_port, socket](const error_code_type&, asio::ip::tcp::resolver::iterator next)->asio::ip::tcp::resolver::iterator
			{
				asio::ip::tcp::endpoint::protocol_type ip_protocol = next->endpoint().protocol();
				socket->close();
				socket->open(ip_protocol);
				socket->bind(asio::ip::tcp::endpoint(ip_protocol, local_port));
				return next;
			},
				[this, local_port, socket](const error_code_type& ec, asio::ip::tcp::resolver::iterator)
			{
				if (!ec)
				{
					std::shared_ptr<pre_session_c> pre_session_c_ptr(std::make_shared<pre_session_c>(local_port, socket, *this, crypto_prov, crypto_srv, main_io_service, misc_io_service));
					std::unique_lock<std::mutex> lock(pre_session_mutex);
					pre_sessions.emplace(pre_session_c_ptr);
					lock.unlock();
					pre_session_c_ptr->start();
				}
				else
				{
					on_exception("Socket Error:" + ec.message());
					free_rand_port(local_port);
				}
			});
		});
	}
}

void server::disconnect(user_id_type id)
{
	leave(id);
}
