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
		if (!ec)
			read_key();
		else
		{
			std::cerr << "Socket Error:" << ec.message() << std::endl;
			if (!exiting)
				srv->pre_session_over(shared_from_this());
		}
	});
}

void pre_session::read_key()
{
	key_buffer = std::make_unique<char[]>(key_length);
	net::async_read(*socket,
		net::buffer(key_buffer.get(), key_length),
		net::transfer_exactly(key_length),
		[this](boost::system::error_code ec, std::size_t length)
	{
		if (!ec)
		{
			stage2();
		}
		else
		{
			std::cerr << "Socket Error:" << ec.message() << std::endl;
			if (!exiting)
				srv->pre_session_over(shared_from_this());
		}
	});
}

void pre_session::read_session_id(bool check_sid)
{
	net::async_read(*socket,
		net::buffer(reinterpret_cast<char*>(&(this->sid_packet_length)), sizeof(data_length_type)),
		net::transfer_exactly(sizeof(data_length_type)),
		[this, check_sid](boost::system::error_code ec, std::size_t length)
	{
		if (!ec)
			read_session_id_body(check_sid);
		else
		{
			std::cerr << "Socket Error:" << ec.message() << std::endl;
			if (!exiting)
				srv->pre_session_over(shared_from_this());
		}
	});
}

void pre_session::read_session_id_body(bool check_sid)
{
	sid_packet_buffer = std::make_unique<char[]>(sid_packet_length);
	net::async_read(*socket,
		net::buffer(sid_packet_buffer.get(), sid_packet_length),
		net::transfer_exactly(sid_packet_length),
		[this, check_sid](boost::system::error_code ec, std::size_t length)
	{
		if (!ec)
		{
			misc_io_service.post([this, check_sid]() {
				std::string raw_data(sid_packet_buffer.get(), sid_packet_length), data;
				decrypt(raw_data, data);

				std::string send_buf(data, sha256_size), sha256_buf(data, 0, sha256_size), sha256_result;
				calcSHA256(send_buf, sha256_result);
				if (sha256_buf != sha256_result)
				{
					std::cerr << "Error:Hashing failed" << std::endl;
					if (!exiting)
						srv->pre_session_over(shared_from_this());
				}
				else
				{
					try
					{
						if (check_sid)
						{
							session_id_type recv_session_id;
							memcpy(reinterpret_cast<char*>(&recv_session_id), send_buf.data(), sizeof(session_id_type));
							if (recv_session_id != session_id)
							{
								std::cerr << "Error:Checking failed" << std::endl;
								if (!exiting)
									srv->pre_session_over(shared_from_this());
								throw(0);
							}
						}
						else
							memcpy(reinterpret_cast<char*>(&session_id), send_buf.data(), sizeof(session_id_type));
						memcpy(reinterpret_cast<char*>(&rand_num), send_buf.data() + sizeof(session_id_type), sizeof(rand_num_type));

						sid_packet_done();
					}
					catch (int) {}
					catch (...) { throw; }
				}
			});
		}
		else
		{
			std::cerr << "Socket Error:" << ec.message() << std::endl;
			if (!exiting)
				srv->pre_session_over(shared_from_this());
		}
	});
}

void pre_session::check_session_id()
{
	net::async_read(*socket,
		net::buffer(reinterpret_cast<char*>(&(this->sid_packet_length)), sizeof(data_length_type)),
		net::transfer_exactly(sizeof(data_length_type)),
		[this](boost::system::error_code ec, std::size_t length)
	{
		if (!ec)
			check_session_id_body();
		else
		{
			std::cerr << "Socket Error:" << ec.message() << std::endl;
			if (!exiting)
				srv->pre_session_over(shared_from_this());
		}
	});
}

void pre_session::check_session_id_body()
{
	sid_packet_buffer = std::make_unique<char[]>(sid_packet_length);
	net::async_read(*socket,
		net::buffer(sid_packet_buffer.get(), sid_packet_length),
		net::transfer_exactly(sid_packet_length),
		[this](boost::system::error_code ec, std::size_t length)
	{
		if (!ec)
		{
			misc_io_service.post([this]() {
				std::string raw_data(sid_packet_buffer.get(), sid_packet_length), data;
				decrypt(raw_data, data);

				std::string send_buf(data, sha256_size), sha256_buf(data, 0, sha256_size), sha256_result;
				calcSHA256(send_buf, sha256_result);
				if (sha256_buf != sha256_result)
				{
					std::cerr << "Error:Hashing failed" << std::endl;
					if (!exiting)
						srv->pre_session_over(shared_from_this());
				}
				else
				{
					session_id_type recv_session_id;
					rand_num_type recv_rand_num;
					memcpy(reinterpret_cast<char*>(&recv_session_id), send_buf.data(), sizeof(session_id_type));
					memcpy(reinterpret_cast<char*>(&recv_rand_num), send_buf.data() + sizeof(session_id_type), sizeof(rand_num_type));

					if ((recv_session_id != session_id) || (recv_rand_num != rand_num))
					{
						std::cerr << "Error:Checking failed" << std::endl;
						if (!exiting)
							srv->pre_session_over(shared_from_this());
					}
					else
					{
						sid_packet_done();
					}
				}
			});
		}
		else
		{
			std::cerr << "Socket Error:" << ec.message() << std::endl;
			if (!exiting)
				srv->pre_session_over(shared_from_this());
		}
	});
}

void pre_session::write_session_id()
{
	misc_io_service.post([this]() {
		std::string send_data, send_raw, sha256_buf;
		sha256_buf.append(reinterpret_cast<char*>(&session_id), sizeof(session_id_type));
		sha256_buf.append(reinterpret_cast<char*>(&rand_num), sizeof(rand_num_type));
		calcSHA256(sha256_buf, send_raw);
		send_raw.append(sha256_buf);
		encrypt(send_raw, send_data, e1);
		insLen(send_data);
		char* send_buf = new char[send_data.size()];
		memcpy(send_buf, send_data.data(), send_data.size());

		net::async_write(*socket,
			net::buffer(send_buf, send_data.size()),
			[this, send_buf](boost::system::error_code ec, std::size_t length)
		{
			delete[] send_buf;
			if (!ec)
			{
				sid_packet_done();
			}
			else
			{
				std::cerr << "Socket Error:" << ec.message() << std::endl;
				if (!exiting)
					srv->pre_session_over(shared_from_this());
			}
		});
	});
}

void pre_session_s::start()
{
	acceptor.async_accept(*socket, [this](boost::system::error_code ec)
	{
		if (!ec)
			stage1();
		else
		{
			std::cerr << "Socket Error:" << ec.message() << std::endl;
			if (!exiting)
				srv->pre_session_over(shared_from_this());
		}
	});
}

void pre_session_s::stage1()
{
	net::async_write(*socket,
		net::buffer(srv->get_public_key()),
		[this](boost::system::error_code ec, std::size_t length)
	{
		if (!ec)
		{
			read_key_header();
		}
		else
		{
			std::cerr << "Socket Error:" << ec.message() << std::endl;
			if (!exiting)
				srv->pre_session_over(shared_from_this());
		}
	});
	acceptor.close();
}

void pre_session_s::stage2()
{
	key_string.assign(key_buffer.get(), key_length);
	CryptoPP::StringSource keySource(key_string, true);
	e1.AccessPublicKey().Load(keySource);

	session_id = boost::endian::native_to_little<rand_num_type>(genRandomNumber());
	rand_num = boost::endian::native_to_little<rand_num_type>(genRandomNumber());
	stage = 0;
	write_session_id();
}

void pre_session_s::sid_packet_done()
{
	switch (stage)
	{
		case 0:
			check_session_id();
			break;
		case 1:
			read_session_id(true);
			break;
		case 2:
			write_session_id();
			break;
		case 3:
		{
			session_ptr newUser(std::make_shared<session>(srv, local_port, std::move(io_service), std::move(socket), e1, session_id));

			newUser->id = srv->join(newUser);
			srv->check_key(newUser->id, key_string);
			newUser->start();

			passed = true;

			if (!exiting)
				srv->pre_session_over(shared_from_this());

			break;
		}
	}
	stage++;
}

void pre_session_c::start()
{
	socket->open(net::ip::tcp::v4());
	socket->bind(net::ip::tcp::endpoint(net::ip::tcp::v4(), local_port));
	socket->async_connect(ep,
		[this](boost::system::error_code ec)
	{
		if (!ec)
			stage1();
		else
		{
			std::cerr << "Socket Error:" << ec.message() << std::endl;
			if (!exiting)
				srv->pre_session_over(shared_from_this());
		}
	});
}

void pre_session_c::stage2()
{
	net::async_write(*socket,
		net::buffer(srv->get_public_key()),
		[this](boost::system::error_code ec, std::size_t length)
	{
		if (!ec)
		{
			key_string.assign(key_buffer.get(), key_length);
			CryptoPP::StringSource keySource(key_string, true);
			e1.AccessPublicKey().Load(keySource);

			read_session_id(false);
		}
		else
		{
			std::cerr << "Socket Error:" << ec.message() << std::endl;
			if (!exiting)
				srv->pre_session_over(shared_from_this());
		}
	});
}

void pre_session_c::sid_packet_done()
{
	switch (stage)
	{
		case 0:
			write_session_id();
			break;
		case 1:
			rand_num = boost::endian::native_to_little<rand_num_type>(genRandomNumber());
			write_session_id();
			break;
		case 2:
			check_session_id();
			break;
		case 3:
		{
			session_ptr newUser(std::make_shared<session>(srv, local_port, std::move(io_service), std::move(socket), e1, session_id));

			newUser->id = srv->join(newUser);
			srv->check_key(newUser->id, key_string);
			newUser->start();

			passed = true;

			if (!exiting)
				srv->pre_session_over(shared_from_this());

			break;
		}
	}
	stage++;
}

void session::start()
{
	read_header();
}

void session::send(const std::string& data, int priority, const std::wstring& message)
{
	if (data.empty())
		return;
	
	std::string write_buf(session_id_in_byte), write_msg;
	calcSHA256(data, write_buf);
	write_buf.append(data);
	encrypt(write_buf, write_msg, e1);
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
