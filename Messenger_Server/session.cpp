#include "stdafx.h"
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
		{
			key_length = boost::endian::little_to_native<key_length_type>(key_length);
			read_key();
		}
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
			key_string.assign(key_buffer.get(), key_length);
			if (srv->check_key_connected(key_string))
			{
				key_string.clear();
				if (!exiting)
					srv->pre_session_over(shared_from_this());
			}
			else
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

void pre_session::read_session_id(int check_level)
{
	net::async_read(*socket,
		net::buffer(reinterpret_cast<char*>(&(this->sid_packet_length)), sizeof(data_length_type)),
		net::transfer_exactly(sizeof(data_length_type)),
		[this, check_level](boost::system::error_code ec, std::size_t length)
	{
		if (!ec)
			read_session_id_body(check_level);
		else
		{
			std::cerr << "Socket Error:" << ec.message() << std::endl;
			if (!exiting)
				srv->pre_session_over(shared_from_this());
		}
	});
}

void pre_session::read_session_id_body(int check_level)
{
	sid_packet_buffer = std::make_unique<char[]>(sid_packet_length);
	net::async_read(*socket,
		net::buffer(sid_packet_buffer.get(), sid_packet_length),
		net::transfer_exactly(sid_packet_length),
		[this, check_level](boost::system::error_code ec, std::size_t length)
	{
		if (!ec)
		{
			misc_io_service.post([this, check_level]() {
				std::string raw_data(sid_packet_buffer.get(), sid_packet_length), data;
				decrypt(raw_data, data);

				std::string hash_recv(data, 0, hash_size), hash_real;
				hash(data, hash_real, hash_size);
				if (hash_recv != hash_real)
				{
					std::cerr << "Error:Hashing failed" << std::endl;
					main_io_service.post([this]() {
						if (!exiting)
							srv->pre_session_over(shared_from_this());
					});
				}
				else
				{
					data.erase(0, hash_size);
					try
					{
						switch (check_level)
						{
							case 0:	//Read only
							{
								memcpy(reinterpret_cast<char*>(&session_id), data.data(), sizeof(session_id_type));
								memcpy(reinterpret_cast<char*>(&rand_num), data.data() + sizeof(session_id_type), sizeof(rand_num_type));
								rand_num = boost::endian::native_to_little<rand_num_type>(boost::endian::little_to_native<rand_num_type>(rand_num) + 1);
								break;
							}
							case 1:	//Check sid
							{
								session_id_type recv_session_id;
								memcpy(reinterpret_cast<char*>(&recv_session_id), data.data(), sizeof(session_id_type));
								if (recv_session_id != session_id)
								{
									std::cerr << "Error:Checking failed" << std::endl;
									main_io_service.post([this]() {
										if (!exiting)
											srv->pre_session_over(shared_from_this());
									});
									throw(0);
								}
								memcpy(reinterpret_cast<char*>(&rand_num), data.data() + sizeof(session_id_type), sizeof(rand_num_type));
								rand_num = boost::endian::native_to_little<rand_num_type>(boost::endian::little_to_native<rand_num_type>(rand_num) + 1);
								break;
							}
							case 2:	//Check all
							{
								session_id_type recv_session_id;
								rand_num_type recv_rand_num;
								memcpy(reinterpret_cast<char*>(&recv_session_id), data.data(), sizeof(session_id_type));
								memcpy(reinterpret_cast<char*>(&recv_rand_num), data.data() + sizeof(session_id_type), sizeof(rand_num_type));

								if ((recv_session_id != session_id) || (recv_rand_num != rand_num + 1))
								{
									std::cerr << "Error:Checking failed" << std::endl;
									main_io_service.post([this]() {
										if (!exiting)
											srv->pre_session_over(shared_from_this());
									});
									throw(0);
								}
								break;
							}
						}

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

void pre_session::write_session_id()
{
	misc_io_service.post([this]() {
		std::string data_encrypted, data_raw, hash_buf;

		hash_buf.append(reinterpret_cast<char*>(&session_id), sizeof(session_id_type));
		hash_buf.append(reinterpret_cast<char*>(&rand_num), sizeof(rand_num_type));

		hash(hash_buf, data_raw);
		data_raw.append(hash_buf);

		encrypt(data_raw, data_encrypted, e1);
		insLen(data_encrypted);

		char* send_buf = new char[data_encrypted.size()];
		memcpy(send_buf, data_encrypted.data(), data_encrypted.size());

		net::async_write(*socket,
			net::buffer(send_buf, data_encrypted.size()),
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
	stage1();
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
}

void pre_session_s::stage2()
{
	try
	{
		CryptoPP::StringSource keySource(key_string, true);
		e1.AccessPublicKey().Load(keySource);

		session_id = boost::endian::native_to_little<rand_num_type>(genRandomNumber());
		rand_num_send = genRandomNumber();
		rand_num = boost::endian::native_to_little<rand_num_type>(rand_num_send);
		if (rand_num_send == std::numeric_limits<rand_num_type>::max())
			rand_num_send = 0;
		else
			rand_num_send++;
		stage = 0;
		write_session_id();
	}
	catch (std::exception &ex)
	{
		std::cerr << ex.what() << std::endl;
		if (!exiting)
			srv->pre_session_over(shared_from_this());
	}
}

void pre_session_s::sid_packet_done()
{
	try
	{
		switch (stage)
		{
			case 0:
				read_session_id(2);
				break;
			case 1:
				read_session_id(1);
				break;
			case 2:
				rand_num_recv = boost::endian::little_to_native<rand_num_type>(rand_num);
				write_session_id();
				break;
			case 3:
			{
				session_ptr new_user(std::make_shared<session>(srv, local_port, main_io_service, misc_io_service, std::move(socket), key_string,
					session_id, rand_num_send, rand_num_recv));

				new_user->id = srv->join(new_user);
				srv->check_key(new_user->id, key_string);
				new_user->start();

				passed = true;

				main_io_service.post([this]() {
					if (!exiting)
						srv->pre_session_over(shared_from_this(), true);
				});

				break;
			}
		}
		stage++;
	}
	catch (std::exception &ex)
	{
		std::cerr << ex.what() << std::endl;
		main_io_service.post([this]() {
			if (!exiting)
				srv->pre_session_over(shared_from_this());
		});
	}
}

void pre_session_c::start()
{
	stage1();
}

void pre_session_c::stage2()
{
	try
	{
		net::async_write(*socket,
			net::buffer(srv->get_public_key()),
			[this](boost::system::error_code ec, std::size_t length)
		{
			if (!ec)
			{
				CryptoPP::StringSource keySource(key_string, true);
				e1.AccessPublicKey().Load(keySource);

				read_session_id(0);
			}
			else
			{
				std::cerr << "Socket Error:" << ec.message() << std::endl;
				if (!exiting)
					srv->pre_session_over(shared_from_this());
			}
		});
	}
	catch (std::exception &ex)
	{
		std::cerr << ex.what() << std::endl;
		if (!exiting)
			srv->pre_session_over(shared_from_this());
	}
}

void pre_session_c::sid_packet_done()
{
	try
	{
		switch (stage)
		{
			case 0:
				rand_num_recv = boost::endian::little_to_native<rand_num_type>(rand_num);
				write_session_id();
				break;
			case 1:
				rand_num_send = genRandomNumber();
				rand_num = boost::endian::native_to_little<rand_num_type>(rand_num_send);
				if (rand_num_send == std::numeric_limits<rand_num_type>::max())
					rand_num_send = 0;
				else
					rand_num_send++;
				write_session_id();
				break;
			case 2:
				read_session_id(2);
				break;
			case 3:
			{
				session_ptr new_user(std::make_shared<session>(srv, local_port, main_io_service, misc_io_service, std::move(socket), key_string,
					session_id, rand_num_send, rand_num_recv));

				new_user->id = srv->join(new_user);
				srv->check_key(new_user->id, key_string);
				new_user->start();

				passed = true;

				main_io_service.post([this]() {
					if (!exiting)
						srv->pre_session_over(shared_from_this());
				});

				break;
			}
		}
		stage++;
	}
	catch (std::exception &ex)
	{
		std::cerr << ex.what() << std::endl;
		main_io_service.post([this]() {
			if (!exiting)
				srv->pre_session_over(shared_from_this());
		});
	}
}

void session::start()
{
	read_header();
}

void session::send(const std::string& data, int priority, write_callback &&callback)
{
	if (data.empty())
		return;
	
	write_task new_task(data, priority, std::move(callback));

	main_iosrv.post([new_task, priority, this]() {
		bool write_not_in_progress = write_que.empty();

		write_que_tp::iterator itr = write_que.begin(), itrEnd = write_que.end();
		for (; itr != itrEnd; itr++)
		{
			if (priority > itr->priority)
			{
				write_que.insert(itr, new_task);
				break;
			}
		}
		if (itr == itrEnd)
			write_que.push_back(new_task);

		if (write_not_in_progress)
		{
			write();
		}
	});
}

void session::stop_file_transfer()
{
	send("", priority_sys, [this]() {
		write_que_tp::iterator itr = write_que.begin(), itrEnd = write_que.end();
		for (; itr != itrEnd;)
		{
			if (itr->priority == priority_file)
				itr = write_que.erase(itr);
			else
				itr++;
		}
	});
}

void session::read_header()
{
	try
	{
		net::async_read(*socket,
			net::buffer(read_msg_buffer.get(), sizeof(data_length_type)),
			net::transfer_exactly(sizeof(data_length_type)),
			[this](boost::system::error_code ec, std::size_t length)
		{
			if (!ec)
			{
				data_length_type size_recv = *(reinterpret_cast<data_length_type*>(read_msg_buffer.get()));
				read_data(size_recv, std::make_shared<std::string>());
			}
			else
			{
				std::cerr << "Socket Error:" << ec.message() << std::endl;
				if (!exiting)
					srv->leave(id);
			}
		});
	}
	catch (std::exception &ex)
	{
		std::cerr << ex.what() << std::endl;
		if (!exiting)
			srv->leave(id);
	}
}

void session::read_data(size_t size_last, std::shared_ptr<std::string> buf)
{
	try
	{
		if (size_last > msg_buffer_size)
		{
			net::async_read(*socket,
				net::buffer(read_msg_buffer.get(), msg_buffer_size),
				net::transfer_exactly(msg_buffer_size),
				[this, size_last, buf](boost::system::error_code ec, std::size_t length)
			{
				if (!ec)
				{
					buf->append(read_msg_buffer.get(), length);
					read_data(size_last - length, buf);
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
				net::buffer(read_msg_buffer.get(), size_last),
				net::transfer_exactly(size_last),
				[this, buf](boost::system::error_code ec, std::size_t length)
			{
				if (!ec)
				{
					buf->append(read_msg_buffer.get(), length);
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
	catch (std::exception &ex)
	{
		std::cerr << ex.what() << std::endl;
		if (!exiting)
			srv->leave(id);
	}
}

void session::write()
{
	write_que_tp::iterator write_itr = write_que.begin(), write_que_end = write_que.end();
	while (write_itr->data.empty())
	{
		write_itr->callback();
		write_itr = write_que.erase(write_itr);
		if (write_itr == write_que_end)
			return;
	}
	rand_num_type rand_num = boost::endian::native_to_little<rand_num_type>(get_rand_num_send());

	misc_iosrv.post([this, write_itr, rand_num]() {
		//data_buf:data with sid and sn; write_raw:data_buf with Hash; write_data:encrypted data, ready for sending
		std::string data_buf, write_raw, write_data;
		data_buf.reserve(sizeof(session_id_type) + sizeof(rand_num_type) + write_itr->data.size());
		data_buf.append(reinterpret_cast<char*>(&session_id), sizeof(session_id_type));
		data_buf.append(reinterpret_cast<const char*>(&rand_num), sizeof(rand_num_type));
		data_buf.append(write_itr->data);
		
		hash(data_buf, write_raw);
		write_raw.append(data_buf);
		encrypt(write_raw, write_data, e1);
		insLen(write_data);
		write_itr->data = std::move(write_data);

		net::async_write(*socket,
			net::buffer(write_itr->data),
			[this, write_itr](boost::system::error_code ec, std::size_t /*length*/)
		{
			if (!ec)
			{
				write_itr->callback();
				write_que.erase(write_itr);
				if (!write_que.empty())
					write();
			}
			else
			{
				std::cerr << "Socket Error:" << ec.message() << std::endl;
				if (!exiting)
					srv->leave(id);
			}
		});
	});
}
