#include "stdafx.h"
#include "crypto.h"
#include "session.h"

using namespace msgr_proto;

void pre_session::write_secret()
{
	misc_io_service.post([this]() {
		dhGen(priv, pubA);
		asio::async_write(*socket,
			asio::buffer(reinterpret_cast<char*>(pubA.data()), pubA.SizeInBytes()),
			[this](boost::system::error_code ec, std::size_t)
		{
			if (!ec)
			{
				read_secret();
			}
			else
			{
				if (!exiting)
				{
					std::cerr << "Socket Error:" << ec.message() << std::endl;
					srv.pre_session_over(shared_from_this());
				}
			}
		});
	});
}

void pre_session::read_secret()
{
	asio::async_read(*socket,
		asio::buffer(reinterpret_cast<char*>(pubB.data()), dh_pub_block_size),
		asio::transfer_exactly(dh_pub_block_size),
		[this](boost::system::error_code ec, std::size_t length)
	{
		if (!ec)
		{
			misc_io_service.post([this]() {
				try
				{
					if (!dhAgree(key, priv, pubB))
						throw(std::runtime_error("Failed to reach shared secret"));
					write_iv();
				}
				catch (std::exception &ex)
				{
					if (!exiting)
					{
						std::cerr << ex.what() << std::endl;
						srv.pre_session_over(shared_from_this());
					}
				}
			});
		}
		else
		{
			if (!exiting)
			{
				std::cerr << "Socket Error:" << ec.message() << std::endl;
				srv.pre_session_over(shared_from_this());
			}
		}
	});
}

void pre_session::write_iv()
{
	std::shared_ptr<CryptoPP::SecByteBlock> iv = std::make_shared<CryptoPP::SecByteBlock>(sym_key_length);
	init_sym_encryption(e, key, *iv);
	asio::async_write(*socket,
		asio::buffer(reinterpret_cast<char*>(iv->data()), iv->SizeInBytes()),
		[this, iv](boost::system::error_code ec, std::size_t)
	{
		if (!ec)
		{
			read_iv();
		}
		else
		{
			if (!exiting)
			{
				std::cerr << "Socket Error:" << ec.message() << std::endl;
				srv.pre_session_over(shared_from_this());
			}
		}
	});
}

void pre_session::read_iv()
{
	asio::async_read(*socket,
		asio::buffer(reinterpret_cast<char*>(iv_buffer), sym_key_length),
		asio::transfer_exactly(sym_key_length),
		[this](boost::system::error_code ec, std::size_t length)
	{
		if (!ec)
		{
			init_sym_decryption(d, key, CryptoPP::SecByteBlock(iv_buffer, sym_key_length));
			stage1();
		}
		else
		{
			if (!exiting)
			{
				std::cerr << "Socket Error:" << ec.message() << std::endl;
				srv.pre_session_over(shared_from_this());
			}
		}
	});
}

void pre_session::read_key_header()
{
	asio::async_read(*socket,
		asio::buffer(reinterpret_cast<char*>(&(this->key_length)), sizeof(key_length_type)),
		asio::transfer_exactly(sizeof(key_length_type)),
		[this](boost::system::error_code ec, std::size_t length)
	{
		if (!ec)
		{
			key_length = boost::endian::little_to_native(key_length);
			read_key();
		}
		else
		{
			if (!exiting)
			{
				std::cerr << "Socket Error:" << ec.message() << std::endl;
				srv.pre_session_over(shared_from_this());
			}
		}
	});
}

void pre_session::read_key()
{
	key_buffer = std::make_unique<char[]>(key_length);
	asio::async_read(*socket,
		asio::buffer(key_buffer.get(), key_length),
		asio::transfer_exactly(key_length),
		[this](boost::system::error_code ec, std::size_t length)
	{
		if (!ec)
		{
			sym_decrypt(std::string(key_buffer.release(), key_length), key_string, d);
			if (srv.check_key_connected(key_string))
			{
				key_string.clear();
				if (!exiting)
					srv.pre_session_over(shared_from_this());
			}
			else
				stage2();
		}
		else
		{
			if (!exiting)
			{
				std::cerr << "Socket Error:" << ec.message() << std::endl;
				srv.pre_session_over(shared_from_this());
			}
		}
	});
}

void pre_session::read_session_id(int check_level, bool ignore_error)
{
	asio::async_read(*socket,
		asio::buffer(reinterpret_cast<char*>(&sid_packet_length), sizeof(data_length_type)),
		asio::transfer_exactly(sizeof(data_length_type)),
		[this, check_level, ignore_error](boost::system::error_code ec, std::size_t length)
	{
		if (!ec)
		{
			read_session_id_body(check_level);
		}
		else
		{
			if (!exiting)
			{
				if (!ignore_error)
					std::cerr << "Socket Error:" << ec.message() << std::endl;
				srv.pre_session_over(shared_from_this());
			}
		}
	});
}

void pre_session::read_session_id_body(int check_level)
{
	sid_packet_buffer = std::make_unique<char[]>(sid_packet_length);
	asio::async_read(*socket,
		asio::buffer(sid_packet_buffer.get(), sid_packet_length),
		asio::transfer_exactly(sid_packet_length),
		[this, check_level](boost::system::error_code ec, std::size_t length)
	{
		if (!ec)
		{
			misc_io_service.post([this, check_level]() {
				std::string raw_data, data(sid_packet_buffer.get(), sid_packet_length);
				sym_decrypt(data, raw_data, d);
				decrypt(raw_data, data);
				

				std::string hash_recv(data, data.size() - hash_size), hash_real;
				hash(data, hash_real, hash_size);
				if (hash_recv != hash_real)
				{
					std::cerr << "Error:Hashing failed" << std::endl;
					main_io_service.post([this]() {
						if (!exiting)
							srv.pre_session_over(shared_from_this());
					});
				}
				else
				{
					try
					{
						switch (check_level)
						{
							case 0:	//Read only
							{
								memcpy(reinterpret_cast<char*>(&session_id), data.data(), sizeof(session_id_type));
								memcpy(reinterpret_cast<char*>(&rand_num), data.data() + sizeof(session_id_type), sizeof(rand_num_type));
								rand_num = boost::endian::native_to_little(boost::endian::little_to_native(rand_num) + 1);
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
											srv.pre_session_over(shared_from_this());
									});
									throw(0);
								}
								memcpy(reinterpret_cast<char*>(&rand_num), data.data() + sizeof(session_id_type), sizeof(rand_num_type));
								rand_num = boost::endian::native_to_little(boost::endian::little_to_native(rand_num) + 1);
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
											srv.pre_session_over(shared_from_this());
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
			if (!exiting)
			{
				std::cerr << "Socket Error:" << ec.message() << std::endl;
				srv.pre_session_over(shared_from_this());
			}
		}
	});
}

void pre_session::write_session_id()
{
	misc_io_service.post([this]() {
		std::string data_buf_2;
		std::shared_ptr<std::string> data_buf_1 = std::make_shared<std::string>();

		data_buf_1->append(reinterpret_cast<char*>(&session_id), sizeof(session_id_type));
		data_buf_1->append(reinterpret_cast<char*>(&rand_num), sizeof(rand_num_type));

		hash(*data_buf_1, *data_buf_1);

		encrypt(*data_buf_1, data_buf_2, e1);
		sym_encrypt(data_buf_2, *data_buf_1, e);
		insLen(*data_buf_1);

		asio::async_write(*socket,
			asio::buffer(data_buf_1->data(), data_buf_1->size()),
			[this, data_buf_1](boost::system::error_code ec, std::size_t length)
		{
			if (!ec)
			{
				sid_packet_done();
			}
			else
			{
				if (!exiting)
				{
					std::cerr << "Socket Error:" << ec.message() << std::endl;
					srv.pre_session_over(shared_from_this());
				}
			}
		});
	});
}

void pre_session_s::start()
{
	write_secret();
}

void pre_session_s::stage1()
{
	std::shared_ptr<std::string> buffer = std::make_shared<std::string>();
	sym_encrypt(srv.get_public_key(), *buffer, e);
	key_length_type e0len = boost::endian::native_to_little(static_cast<key_length_type>(buffer->size()));
	buffer->insert(0, std::string(reinterpret_cast<const char*>(&e0len), sizeof(key_length_type)));

	asio::async_write(*socket,
		asio::buffer(*buffer),
		[this, buffer](boost::system::error_code ec, std::size_t length)
	{
		if (!ec)
		{
			read_key_header();
		}
		else
		{
			if (!exiting)
			{
				std::cerr << "Socket Error:" << ec.message() << std::endl;
				srv.pre_session_over(shared_from_this());
			}
		}
	});
}

void pre_session_s::stage2()
{
	try
	{
		CryptoPP::StringSource keySource(key_string, true);
		e1.AccessPublicKey().Load(keySource);

		session_id = boost::endian::native_to_little(genRandomNumber());
		rand_num_send = genRandomNumber();
		rand_num = boost::endian::native_to_little(rand_num_send);
		if (rand_num_send == std::numeric_limits<rand_num_type>::max())
			rand_num_send = 0;
		else
			rand_num_send++;
		stage = 0;
		write_session_id();
	}
	catch (std::exception &ex)
	{
		if (!exiting)
		{
			std::cerr << ex.what() << std::endl;
			srv.pre_session_over(shared_from_this());
		}
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
				rand_num_recv = boost::endian::little_to_native(rand_num);
				write_session_id();
				break;
			case 3:
			{
				session_ptr new_user(std::make_shared<session>(srv, local_port, key_string, std::move(proto_data),
					main_io_service, misc_io_service, std::move(socket)));

				srv.join(new_user);
				new_user->start();

				passed = true;

				main_io_service.post([this]() {
					if (!exiting)
						srv.pre_session_over(shared_from_this(), true);
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
				srv.pre_session_over(shared_from_this());
		});
	}
}

void pre_session_c::start()
{
	write_secret();
}

void pre_session_c::stage2()
{
	std::shared_ptr<std::string> buffer = std::make_shared<std::string>();
	sym_encrypt(srv.get_public_key(), *buffer, e);
	key_length_type e0len = boost::endian::native_to_little(static_cast<key_length_type>(buffer->size()));
	buffer->insert(0, std::string(reinterpret_cast<const char*>(&e0len), sizeof(key_length_type)));

	asio::async_write(*socket,
		asio::buffer(*buffer),
		[this, buffer](boost::system::error_code ec, std::size_t length)
	{
		try
		{
			if (ec)
				throw(std::runtime_error("Socket Error:" + ec.message()));
			CryptoPP::StringSource keySource(key_string, true);
			e1.AccessPublicKey().Load(keySource);

			read_session_id(0, true);
		}
		catch (std::exception &ex)
		{
			if (!exiting)
			{
				std::cerr << ex.what() << std::endl;
				srv.pre_session_over(shared_from_this());
			}
		}
	});
}

void pre_session_c::sid_packet_done()
{
	try
	{
		switch (stage)
		{
			case 0:
				rand_num_recv = boost::endian::little_to_native(rand_num);
				write_session_id();
				break;
			case 1:
				rand_num_send = genRandomNumber();
				rand_num = boost::endian::native_to_little(rand_num_send);
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
				session_ptr new_user(std::make_shared<session>(srv, local_port, key_string, std::move(proto_data),
					main_io_service, misc_io_service, std::move(socket)));

				srv.join(new_user);
				new_user->start();

				passed = true;

				main_io_service.post([this]() {
					if (!exiting)
						srv.pre_session_over(shared_from_this());
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
				srv.pre_session_over(shared_from_this());
		});
	}
}

void virtual_session::send(const std::string& data, int priority, write_callback &&callback)
{
	on_data(data);
	callback();
}

void virtual_session::push(const std::string& data)
{
	srv.on_data(uid, std::make_shared<std::string>(data));
}

void virtual_session::push(std::string&& data)
{
	srv.on_data(uid, std::make_shared<std::string>(data));
}

void session::start()
{
	read_header();
}

void session::shutdown()
{
	exiting = true;
	boost::system::error_code ec;
	socket->shutdown(socket->shutdown_both, ec);
	socket->close(ec);
	for (const write_task &task : write_que)
		task.callback();
}

void session::send(const std::string& data, int priority, write_callback &&callback)
{
	session_ptr self = shared_from_this();
	if (data.empty())
		return;
	
	write_task new_task(data, priority, std::move(callback));

	main_iosrv.post([this, self, new_task, priority]() {
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

void session::read_header()
{
	try
	{
		session_ptr self = shared_from_this();
		asio::async_read(*socket,
			asio::buffer(read_buffer.get(), sizeof(data_length_type)),
			asio::transfer_exactly(sizeof(data_length_type)),
			[this, self](boost::system::error_code ec, std::size_t length)
		{
			if (!ec)
			{
				data_length_type size_recv = *(reinterpret_cast<data_length_type*>(read_buffer.get()));
				size_recv = boost::endian::little_to_native(size_recv);
				read_data(size_recv, std::make_shared<std::string>());
			}
			else
			{
				if (!exiting)
				{
					if (length != 0)
						std::cerr << "Socket Error:" << ec.message() << std::endl;
					srv.leave(uid);
				}
			}
		});
	}
	catch (std::exception &ex)
	{
		if (!exiting)
		{
			std::cerr << ex.what() << std::endl;
			srv.leave(uid);
		}
	}
}

void session::read_data(size_t size_last, const std::shared_ptr<std::string> &buf)
{
	try
	{
		session_ptr self = shared_from_this();
		if (size_last > read_buffer_size)
		{
			asio::async_read(*socket,
				asio::buffer(read_buffer.get(), read_buffer_size),
				asio::transfer_exactly(read_buffer_size),
				[this, self, size_last, buf](boost::system::error_code ec, std::size_t length)
			{
				if (!ec)
				{
					buf->append(read_buffer.get(), length);
					read_data(size_last - length, buf);
				}
				else
				{
					if (!exiting)
					{
						std::cerr << "Socket Error:" << ec.message() << std::endl;
						srv.leave(uid);
					}
				}
			});
		}
		else
		{
			asio::async_read(*socket,
				asio::buffer(read_buffer.get(), size_last),
				asio::transfer_exactly(size_last),
				[this, self, buf](boost::system::error_code ec, std::size_t length)
			{
				if (!ec)
				{
					buf->append(read_buffer.get(), length);
					process_data(buf);
					start();
				}
				else
				{
					if (!exiting)
					{
						std::cerr << "Socket Error:" << ec.message() << std::endl;
						srv.leave(uid);
					}
				}
			});
		}
	}
	catch (std::exception &ex)
	{
		if (!exiting)
		{
			std::cerr << ex.what() << std::endl;
			srv.leave(uid);
		}
	}
}

void session::process_data(const std::shared_ptr<std::string> &buf)
{
	session_ptr self = shared_from_this();

	misc_iosrv.post([this, self, buf]() {
		std::string decrypted_data;
		sym_decrypt(*buf, decrypted_data, d);
		decrypt(decrypted_data, *buf);

		std::string hash_real;
		hash(*buf, hash_real, hash_size);

		main_iosrv.post([this, self, buf, hash_real]() {
			const char *itr = buf->data() + buf->size() - hash_size;
			std::string hash_recv(itr, hash_size);
			if (hash_real != hash_recv)
			{
				std::cerr << "Error:Hashing failed" << std::endl;
				srv.leave(uid);
				return;
			}

			itr -= sizeof(rand_num_type);
			rand_num_type rand_num = boost::endian::native_to_little(get_rand_num_recv());
			if (*reinterpret_cast<const rand_num_type*>(itr) != rand_num)
			{
				std::cerr << "Error:Checking failed" << std::endl;
				srv.leave(uid);
				return;
			}

			itr -= sizeof(session_id_type);
			if (*reinterpret_cast<const session_id_type*>(itr) != session_id)
			{
				std::cerr << "Error:Checking failed" << std::endl;
				srv.leave(uid);
				return;
			}

			buf->erase(buf->size() - (sizeof(session_id_type) + sizeof(rand_num_type) + hash_size));
			
			srv.on_data(uid, buf);
		});
	});
}

void session::write()
{
	session_ptr self = shared_from_this();

	write_que_tp::iterator write_itr = write_que.begin(), write_que_end = write_que.end();
	while (write_itr->data.empty())
	{
		write_itr->callback();
		write_itr = write_que.erase(write_itr);
		if (write_itr == write_que_end)
			return;
	}
	rand_num_type rand_num = boost::endian::native_to_little(get_rand_num_send());

	misc_iosrv.post([this, self, write_itr, rand_num]() {
		std::string write_raw, write_data;
		write_raw.reserve(sizeof(session_id_type) + sizeof(rand_num_type) + write_itr->data.size() + hash_size);
		write_raw.append(write_itr->data);
		write_raw.append(reinterpret_cast<char*>(&session_id), sizeof(session_id_type));
		write_raw.append(reinterpret_cast<const char*>(&rand_num), sizeof(rand_num_type));
		hash(write_raw, write_raw);

		encrypt(write_raw, write_data, e1);
		sym_encrypt(write_data, write_raw, e);
		insLen(write_raw);
		write_itr->data = std::move(write_raw);

		asio::async_write(*socket,
			asio::buffer(write_itr->data),
			[this, self, write_itr](boost::system::error_code ec, std::size_t /*length*/)
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
				if (!exiting)
				{
					std::cerr << "Socket Error:" << ec.message() << std::endl;
					srv.leave(uid);
				}
			}
		});
	});
}
