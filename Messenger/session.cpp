#include "stdafx.h"
#include "global.h"
#include "crypto.h"
#include "session.h"

void pre_session::read_key_header()
{
	net::async_read(*socket,
		net::buffer(reinterpret_cast<char*>(&(this->key_length)), sizeof(key_length_type)),
		net::transfer_exactly(sizeof(key_length_type)),
		[this](boost::system::error_code ec, std::size_t length)
	{
		if (ec)
		{
			std::cerr << "Socket Error:" << ec.message() << std::endl;
			if (!exiting)
				srv->pre_session_over(shared_from_this());
		}
		else
			read_key();
	});
}

void pre_session::read_key()
{
	key_buffer = new char[key_length];
	net::async_read(*socket,
		net::buffer(key_buffer, key_length),
		net::transfer_exactly(key_length),
		[this](boost::system::error_code ec, std::size_t length)
	{
		if (ec)
		{
			std::cerr << "Socket Error:" << ec.message() << std::endl;
			if (!exiting)
				srv->pre_session_over(shared_from_this());
		}
		else
		{
			stage2();
		}
	});
}

void pre_session_s::start()
{
	acceptor.async_accept(*socket, [this](boost::system::error_code ec)
	{
		if (ec)
		{
			std::cerr << "Socket Error:" << ec.message() << std::endl;
			if (!exiting)
				srv->pre_session_over(shared_from_this());
		}
		else
			stage1();
	});
}

void pre_session_s::stage1()
{
	net::async_write(*socket,
		net::buffer(srv->get_public_key()),
		[this](boost::system::error_code ec, std::size_t length)
	{
		if (ec)
		{
			std::cerr << "Socket Error:" << ec.message() << std::endl;
			if (!exiting)
				srv->pre_session_over(shared_from_this());
		}
		else
		{
			read_key_header();
		}
	});
	acceptor.close();
}

void pre_session_s::stage2()
{
	session_ptr newUser(std::make_shared<session>(srv, local_port, std::move(io_service), std::move(socket)));

	session &item = *newUser;
	std::string key_string(key_buffer, key_length);
	CryptoPP::StringSource keySource(key_string, true);
	item.e1.AccessPublicKey().Load(keySource);

	newUser->id = srv->join(newUser);
	srv->check_key(newUser->id, key_string);
	newUser->start();

	passed = true;

	if (!exiting)
		srv->pre_session_over(shared_from_this());
}

void pre_session_c::start()
{
	socket->open(net::ip::tcp::v4());
	socket->bind(net::ip::tcp::endpoint(net::ip::tcp::v4(), local_port));
	socket->async_connect(ep,
		[this](boost::system::error_code ec)
	{
		if (ec)
		{
			std::cerr << "Socket Error:" << ec.message() << std::endl;
			if (!exiting)
				srv->pre_session_over(shared_from_this());
		}
		else
			stage1();
	});
}

void pre_session_c::stage2()
{
	net::async_write(*socket,
		net::buffer(srv->get_public_key()),
		[this](boost::system::error_code ec, std::size_t length)
	{
		if (ec)
		{
			std::cerr << "Socket Error:" << ec.message() << std::endl;
		}
		else
		{
			session_ptr newUser(std::make_shared<session>(srv, local_port, std::move(io_service), std::move(socket)));

			session &item = *newUser;
			std::string key_string(key_buffer, key_length);
			CryptoPP::StringSource keySource(key_string, true);
			item.e1.AccessPublicKey().Load(keySource);

			newUser->id = srv->join(newUser);
			srv->check_key(newUser->id, key_string);
			newUser->start();
			
			passed = true;
		}
		if (!exiting)
			srv->pre_session_over(shared_from_this());
	});
}

void session::start()
{
	read_header();
}

void session::send(const std::string& data, int priority, const std::wstring& message)
{
	if (data.empty())
		return;
	
	std::string write_msg;
	encrypt(data, write_msg, e1);
	insLen(write_msg);

	io_service.post([write_msg, message, priority, this]() {
		bool write_not_in_progress = write_que.empty();
		write_que_tp::iterator itr = write_que.begin(), itrEnd = write_que.end();
		for (; itr != itrEnd; itr++)
		{
			if (priority > itr->priority)
			{
				write_que.insert(itr, write_task(std::move(write_msg), priority, std::move(message)));
				break;
			}
		}
		if (itr == itrEnd)
			write_que.push_back(write_task(std::move(write_msg), priority, std::move(message)));

		if (write_not_in_progress)
		{
			write();
		}
	});
}

void session::read_header()
{
	net::async_read(*socket,
		net::buffer(read_msg_buffer, sizeof(data_length_type)),
		net::transfer_exactly(sizeof(data_length_type)),
		[this](boost::system::error_code ec, std::size_t length)
	{
		if (!ec)
		{
			data_length_type sizeRecv = *(reinterpret_cast<data_length_type*>(read_msg_buffer));
			read_data(sizeRecv, std::make_shared<std::string>());
		}
		else
		{
			std::cerr << "Socket Error:" << ec.message() << std::endl;
			if (!exiting)
				srv->leave(id);
		}
	});
}

void session::read_data(size_t sizeLast, std::shared_ptr<std::string> buf)
{
	try
	{
		if (sizeLast > msg_buffer_size)
		{
			net::async_read(*socket,
				net::buffer(read_msg_buffer, msg_buffer_size),
				net::transfer_exactly(msg_buffer_size),
				[this, sizeLast, buf](boost::system::error_code ec, std::size_t length)
			{
				if (!ec)
				{
					buf->append(read_msg_buffer, length);
					read_data(sizeLast - length, buf);
				}
				else
				{
					std::cerr << "Socket Error:" << ec.message() << std::endl;
					if (!exiting)
						srv->leave(id);
				}
			});
		}
		else
		{
			net::async_read(*socket,
				net::buffer(read_msg_buffer, sizeLast),
				net::transfer_exactly(sizeLast),
				[this, buf](boost::system::error_code ec, std::size_t length)
			{
				if (!ec)
				{
					buf->append(read_msg_buffer, length);
					srv->on_data(id, buf);
					start();
				}
				else
				{
					std::cerr << "Socket Error:" << ec.message() << std::endl;
					if (!exiting)
						srv->leave(id);
				}
			});
		}
	}
	catch (std::runtime_error ex)
	{
		std::cerr << ex.what() << std::endl;
		if (!exiting)
			srv->leave(id);
	}
}

void session::write()
{
	write_que_tp::iterator write_itr = write_que.begin();
	net::async_write(*socket,
		net::buffer(write_itr->data),
		[this, write_itr](boost::system::error_code ec, std::size_t /*length*/)
	{
		if (!ec)
		{
			if (!write_itr->msg.empty())
				std::cout << write_itr->msg << std::endl;
			write_que.erase(write_itr);
			if (!write_que.empty())
			{
				write();
			}
		}
		else
		{
			std::cerr << "Socket Error:" << ec.message() << std::endl;
			if (!exiting)
				srv->leave(id);
		}
	});
}
