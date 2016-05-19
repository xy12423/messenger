#include "stdafx.h"
#include "crypto.h"
#include "session.h"

using namespace msgr_proto;

void pre_session::read_key_header()
{
	asio::async_read(*socket,
		asio::buffer(reinterpret_cast<char*>(&(this->key_size)), sizeof(key_size_type)),
		asio::transfer_exactly(sizeof(key_size_type)),
		[this](boost::system::error_code ec, std::size_t size)
	{
		try
		{
			if (ec)
				throw(std::runtime_error("Socket Error:" + ec.message()));
			key_size = boost::endian::little_to_native(key_size);
			read_key();
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

void pre_session::read_key()
{
	key_buffer = std::make_unique<char[]>(key_size);
	asio::async_read(*socket,
		asio::buffer(key_buffer.get(), key_size),
		asio::transfer_exactly(key_size),
		[this](boost::system::error_code ec, std::size_t size)
	{
		try
		{
			if (ec)
				throw(std::runtime_error("Socket Error:" + ec.message()));
			key_string.assign(key_buffer.release(), key_size);
			if (srv.check_key_connected(key_string))
			{
				key_string.clear();
				if (!exiting)
					srv.pre_session_over(shared_from_this());
			}
			else
				stage1();
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

void pre_session::write_secret()
{
	misc_io_service.post([this]() {
		dhGen(priv, pubA);
		std::shared_ptr<std::string> buf = std::make_shared<std::string>();
		encrypt(pubA.BytePtr(), pubA.SizeInBytes(), *buf, e1);
		key_size_type len = boost::endian::native_to_little(static_cast<key_size_type>(buf->size()));
		buf->insert(0, reinterpret_cast<const char*>(&len), sizeof(key_size_type));

		asio::async_write(*socket,
			asio::buffer(buf->data(), buf->size()),
			[this, buf](boost::system::error_code ec, std::size_t)
		{
			try
			{
				if (ec)
					throw(std::runtime_error("Socket Error:" + ec.message()));
				read_secret_header();
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
	});
}

void pre_session::read_secret_header()
{
	asio::async_read(*socket,
		asio::buffer(reinterpret_cast<char*>(&(this->pubB_size)), sizeof(key_size_type)),
		asio::transfer_exactly(sizeof(key_size_type)),
		[this](boost::system::error_code ec, std::size_t size)
	{
		try
		{
			if (ec)
				throw(std::runtime_error("Socket Error:" + ec.message()));
			pubB_size = boost::endian::little_to_native(pubB_size);
			read_secret();
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

void pre_session::read_secret()
{
	pubB_buffer = std::make_unique<char[]>(pubB_size);
	asio::async_read(*socket,
		asio::buffer(pubB_buffer.get(), pubB_size),
		asio::transfer_exactly(pubB_size),
		[this](boost::system::error_code ec, std::size_t size)
	{
		if (!ec)
		{
			misc_io_service.post([this]() {
				try
				{
					decrypt(reinterpret_cast<byte*>(pubB_buffer.get()), pubB_size, pubB);
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
	std::shared_ptr<CryptoPP::SecByteBlock> iv = std::make_shared<CryptoPP::SecByteBlock>(sym_key_size);
	init_sym_encryption(e, key, *iv);
	asio::async_write(*socket,
		asio::buffer(reinterpret_cast<char*>(iv->data()), iv->SizeInBytes()),
		[this, iv](boost::system::error_code ec, std::size_t)
	{
		try
		{
			if (ec)
				throw(std::runtime_error("Socket Error:" + ec.message()));
			read_iv();
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

void pre_session::read_iv()
{
	asio::async_read(*socket,
		asio::buffer(reinterpret_cast<char*>(iv_buffer), sym_key_size),
		asio::transfer_exactly(sym_key_size),
		[this](boost::system::error_code ec, std::size_t size)
	{
		try
		{
			if (ec)
				throw(std::runtime_error("Socket Error:" + ec.message()));
			init_sym_decryption(d, key, CryptoPP::SecByteBlock(iv_buffer, sym_key_size));
			stage2();
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

void pre_session::read_session_id(int check_level, bool ignore_error)
{
	asio::async_read(*socket,
		asio::buffer(reinterpret_cast<char*>(&sid_packet_size), sizeof(data_size_type)),
		asio::transfer_exactly(sizeof(data_size_type)),
		[this, check_level, ignore_error](boost::system::error_code ec, std::size_t size)
	{
		try
		{
			if (ec)
				throw(std::runtime_error("Socket Error:" + ec.message()));
			read_session_id_body(check_level);
		}
		catch (std::exception &ex)
		{
			if (!exiting)
			{
				if (!ignore_error)
					std::cerr << ex.what() << std::endl;
				srv.pre_session_over(shared_from_this());
			}
		}
	});
}

void pre_session::read_session_id_body(int check_level)
{
	sid_packet_buffer = std::make_unique<char[]>(sid_packet_size);
	asio::async_read(*socket,
		asio::buffer(sid_packet_buffer.get(), sid_packet_size),
		asio::transfer_exactly(sid_packet_size),
		[this, check_level](boost::system::error_code ec, std::size_t size)
	{
		if (!ec)
		{
			misc_io_service.post([this, check_level]() {
				try
				{
					std::string raw_data, data(sid_packet_buffer.get(), sid_packet_size);
					decrypt(data, raw_data);
					sym_decrypt(raw_data, data, d);
					

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
				}
				catch (int) {}
				catch (std::exception &ex)
				{
					std::cerr << ex.what() << std::endl;
					main_io_service.post([this]() {
						if (!exiting)
							srv.pre_session_over(shared_from_this());
					});
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

		sym_encrypt(*data_buf_1, data_buf_2, e);
		encrypt(data_buf_2, *data_buf_1, e1);
		
		insLen(*data_buf_1);

		asio::async_write(*socket,
			asio::buffer(data_buf_1->data(), data_buf_1->size()),
			[this, data_buf_1](boost::system::error_code ec, std::size_t size)
		{
			try
			{
				if (ec)
					throw(std::runtime_error("Socket Error:" + ec.message()));
				sid_packet_done();
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
	});
}

void pre_session_s::start()
{
	std::shared_ptr<std::string> buffer = std::make_shared<std::string>(srv.get_public_key());
	key_size_type e0len = boost::endian::native_to_little(static_cast<key_size_type>(buffer->size()));
	buffer->insert(0, reinterpret_cast<const char*>(&e0len), sizeof(key_size_type));

	asio::async_write(*socket,
		asio::buffer(*buffer),
		[this, buffer](boost::system::error_code ec, std::size_t size)
	{
		try
		{
			if (ec)
				throw(std::runtime_error("Socket Error:" + ec.message()));
			read_key_header();
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

void pre_session_s::stage1()
{
	try
	{
		CryptoPP::StringSource keySource(key_string, true);
		e1.AccessPublicKey().Load(keySource);

		write_secret();
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

void pre_session_s::stage2()
{
	try
	{
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
	std::shared_ptr<std::string> buffer = std::make_shared<std::string>(srv.get_public_key());
	key_size_type e0len = boost::endian::native_to_little(static_cast<key_size_type>(buffer->size()));
	buffer->insert(0, reinterpret_cast<const char*>(&e0len), sizeof(key_size_type));

	asio::async_write(*socket,
		asio::buffer(*buffer),
		[this, buffer](boost::system::error_code ec, std::size_t size)
	{
		try
		{
			if (ec)
				throw(std::runtime_error("Socket Error:" + ec.message()));
			read_key_header();
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

void pre_session_c::stage1()
{
	try
	{
		CryptoPP::StringSource keySource(key_string, true);
		e1.AccessPublicKey().Load(keySource);

		write_secret();
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

void pre_session_c::stage2()
{
	try
	{
		stage = 0;
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

void virtual_session::send(const std::string& data, int priority, write_callback&& callback)
{
	on_data(data);
	callback();
}

void virtual_session::send(std::string&& data, int priority, write_callback&& callback)
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

void session::send(const std::string& data, int priority, write_callback&& callback)
{
	session_ptr self = shared_from_this();
	if (data.empty())
		return;
	
	std::shared_ptr<write_task> new_task = std::make_shared<write_task>(data, priority, std::move(callback));

	main_iosrv.post([this, self, new_task, priority]() {
		bool write_not_in_progress = write_que.empty();

		write_que_tp::iterator itr = write_que.begin(), itrEnd = write_que.end();
		for (; itr != itrEnd; itr++)
		{
			if (priority > itr->priority)
			{
				write_que.insert(itr, std::move(*new_task));
				break;
			}
		}
		if (itr == itrEnd)
			write_que.push_back(std::move(*new_task));

		if (write_not_in_progress)
		{
			write();
		}
	});
}

void session::send(std::string&& data, int priority, write_callback&& callback)
{
	session_ptr self = shared_from_this();
	if (data.empty())
		return;

	std::shared_ptr<write_task> new_task = std::make_shared<write_task>(std::move(data), priority, std::move(callback));

	main_iosrv.post([this, self, new_task, priority]() {
		bool write_not_in_progress = write_que.empty();

		write_que_tp::iterator itr = write_que.begin(), itrEnd = write_que.end();
		for (; itr != itrEnd; itr++)
		{
			if (priority > itr->priority)
			{
				write_que.insert(itr, std::move(*new_task));
				break;
			}
		}
		if (itr == itrEnd)
			write_que.push_back(std::move(*new_task));

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
			asio::buffer(read_buffer.get(), sizeof(data_size_type)),
			asio::transfer_exactly(sizeof(data_size_type)),
			[this, self](boost::system::error_code ec, std::size_t size)
		{
			try
			{
				if (ec)
					throw(std::runtime_error("Socket Error:" + ec.message()));
				data_size_type size_recv = *(reinterpret_cast<data_size_type*>(read_buffer.get()));
				size_recv = boost::endian::little_to_native(size_recv);
				read_data(size_recv, std::make_shared<std::string>());
			}
			catch (std::exception &ex)
			{
				if (!exiting)
				{
					if (size != 0)
						std::cerr << ex.what() << std::endl;
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

void session::read_data(size_t size_last, const std::shared_ptr<std::string>& buf)
{
	try
	{
		session_ptr self = shared_from_this();
		if (size_last > read_buffer_size)
		{
			asio::async_read(*socket,
				asio::buffer(read_buffer.get(), read_buffer_size),
				asio::transfer_exactly(read_buffer_size),
				[this, self, size_last, buf](boost::system::error_code ec, std::size_t size)
			{
				try
				{
					if (ec)
						throw(std::runtime_error("Socket Error:" + ec.message()));
					buf->append(read_buffer.get(), size);
					read_data(size_last - size, buf);
				}
				catch (std::exception &ex)
				{
					if (!exiting)
					{
						std::cerr << ex.what() << std::endl;
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
				[this, self, buf](boost::system::error_code ec, std::size_t size)
			{
				try
				{
					if (ec)
						throw(std::runtime_error("Socket Error:" + ec.message()));
					buf->append(read_buffer.get(), size);
					process_data(buf);
					start();
				}
				catch (std::exception &ex)
				{
					if (!exiting)
					{
						std::cerr << ex.what() << std::endl;
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

void session::process_data(const std::shared_ptr<std::string>& buf)
{
	session_ptr self = shared_from_this();

	misc_iosrv.post([this, self, buf]() {
		std::string decrypted_data;
		
		decrypt(*buf, decrypted_data);
		sym_decrypt(decrypted_data, *buf, d);

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
		std::string &write_raw = write_itr->data, write_data;
		write_raw.reserve(sizeof(session_id_type) + sizeof(rand_num_type) + write_raw.size() + hash_size);
		write_raw.append(reinterpret_cast<char*>(&session_id), sizeof(session_id_type));
		write_raw.append(reinterpret_cast<const char*>(&rand_num), sizeof(rand_num_type));
		hash(write_raw, write_raw);

		sym_encrypt(write_raw, write_data, e);
		encrypt(write_data, write_raw, e1);
		insLen(write_raw);

		asio::async_write(*socket,
			asio::buffer(write_itr->data),
			[this, self, write_itr](boost::system::error_code ec, std::size_t /*length*/)
		{
			try
			{
				if (ec)
					throw(std::runtime_error("Socket Error:" + ec.message()));
				write_itr->callback();
				write_que.erase(write_itr);
				if (!write_que.empty())
					write();
			}
			catch (std::exception &ex)
			{
				if (!exiting)
				{
					std::cerr << ex.what() << std::endl;
					srv.leave(uid);
				}
			}
		});
	});
}
