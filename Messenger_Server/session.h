#pragma once

#ifndef _H_SESSION
#define _H_SESSION

typedef uint16_t key_length_type;
typedef uint32_t data_length_type;

typedef uint16_t port_type;
typedef int32_t port_type_l;
const port_type_l port_null = -1;

typedef uint16_t user_id_type;
typedef uint64_t session_id_type;

typedef std::shared_ptr<asio::ip::tcp::socket> socket_ptr;

void insLen(std::string &data);

class server;

class pre_session : public std::enable_shared_from_this<pre_session>
{
public:
	pre_session(server &_srv, port_type_l _local_port, asio::io_service &main_io_srv, asio::io_service &misc_io_srv, const socket_ptr &_socket)
		:srv(_srv),
		main_io_service(main_io_srv),
		misc_io_service(misc_io_srv),
		socket(_socket)
	{
		local_port = _local_port;
	}

	~pre_session() { if (!passed) { exiting = true; socket->close(); } }

	port_type_l get_port() const { return local_port; }
	const std::string& get_key() const { return key_string; }

	virtual void start() = 0;
private:
	virtual void stage1() = 0;
	virtual void stage2() = 0;
	virtual void sid_packet_done() = 0;
protected:
	void read_key_header(bool ignore_error = false);
	void read_key();

	void read_session_id(int check_level, bool ignore_error = false);
	void read_session_id_body(int check_level);
	void write_session_id();

	key_length_type key_length;
	std::unique_ptr<char[]> key_buffer;
	std::string key_string;

	data_length_type sid_packet_length;
	std::unique_ptr<char[]> sid_packet_buffer;
	int stage = 0;

	CryptoPP::ECIES<CryptoPP::ECP>::Encryptor e1;
	session_id_type session_id;
	rand_num_type rand_num;
	rand_num_type rand_num_send, rand_num_recv;

	asio::io_service &main_io_service, &misc_io_service;
	socket_ptr socket;

	server &srv;
	port_type_l local_port;
	volatile bool exiting = false, passed = false;
};

class pre_session_s :public pre_session
{
public:
	pre_session_s(port_type_l local_port, const socket_ptr &_socket, server &_srv, asio::io_service &main_io_srv, asio::io_service &misc_io_srv)
		:pre_session(_srv, local_port, main_io_srv, misc_io_srv, _socket)
	{
		start();
	}

	virtual void start();
private:
	virtual void stage1();
	virtual void stage2();
	virtual void sid_packet_done();
};

class pre_session_c :public pre_session
{
public:
	pre_session_c(port_type_l local_port, const socket_ptr &_socket, server &_srv, asio::io_service &main_io_srv, asio::io_service &misc_io_srv)
		:pre_session(_srv, local_port, main_io_srv, misc_io_srv, _socket)
	{
		start();
	}

	virtual void start();
private:
	virtual void stage1() { read_key_header(); };
	virtual void stage2();
	virtual void sid_packet_done();
};

class session_base : public std::enable_shared_from_this<session_base>
{
public:
	static const int priority_sys = 30;
	static const int priority_msg = 20;
	static const int priority_plugin = 15;
	static const int priority_file = 10;

	typedef std::function<void()> write_callback;

	session_base(server &_srv, port_type_l _local_port, const std::string &_key_string)
		:srv(_srv), local_port(_local_port), key_string(_key_string)
	{}

	virtual void start() = 0;
	virtual void shutdown() = 0;

	virtual void send(const std::string& data, int priority, write_callback &&callback) = 0;

	virtual std::string get_address() const = 0;
	user_id_type get_id() const { return uid; }
	port_type_l get_port() const { return local_port; }
	const std::string& get_key() const { return key_string; }

	friend class server;
protected:
	std::string key_string;
	user_id_type uid;

	server &srv;
	port_type_l local_port;
};
typedef std::shared_ptr<session_base> session_ptr;
typedef std::unordered_map<user_id_type, session_ptr> session_list_type;

class virtual_session :public session_base
{
public:
	typedef std::function<void(const std::string &)> on_data_callback;

	virtual_session(server &_srv, const std::string &_name)
		:session_base(_srv, port_null, ""), name(_name)
	{}

	void start() {};
	void shutdown() {};

	void send(const std::string& data, int priority, write_callback &&callback);

	void push(const std::string& data);
	void push(std::string&& data);

	std::string get_address() const { return name; }

	void set_callback(on_data_callback &&_callback) { on_data = _callback; }
private:
	std::string name;
	on_data_callback on_data;
};

class session : public session_base
{
public:
	session(server &_srv, port_type_l _local_port, const std::string &_key_string,
		asio::io_service& _main_iosrv, asio::io_service& _misc_iosrv, socket_ptr &&_socket,
		session_id_type _session_id, rand_num_type _rand_num_send, rand_num_type _rand_num_recv)
		:session_base(_srv, _local_port, _key_string),
		main_iosrv(_main_iosrv), misc_iosrv(_misc_iosrv), socket(_socket),
		session_id(_session_id), rand_num_send(_rand_num_send), rand_num_recv(_rand_num_recv)
	{
		read_msg_buffer = std::make_unique<char[]>(msg_buffer_size);

		CryptoPP::StringSource keySource(key_string, true);
		e1.AccessPublicKey().Load(keySource);
	}

	~session()
	{
		if (!exiting)
		{
			try
			{
				shutdown();
			}
			catch (...) {}
		}
	}

	void start();
	void shutdown();

	void send(const std::string& data, int priority, write_callback &&callback);

	std::string get_address() const { return socket->remote_endpoint().address().to_string(); }
private:
	void read_header();
	void read_data(size_t sizeLast, std::shared_ptr<std::string> buf);
	void process_data(std::shared_ptr<std::string> buf);
	void write();

	inline rand_num_type get_rand_num_send() { if (rand_num_send == std::numeric_limits<rand_num_type>::max()) rand_num_send = 0; else rand_num_send++; return rand_num_send; };
	inline rand_num_type get_rand_num_recv() { if (rand_num_recv == std::numeric_limits<rand_num_type>::max()) rand_num_recv = 0; else rand_num_recv++; return rand_num_recv; };

	CryptoPP::ECIES<CryptoPP::ECP>::Encryptor e1;
	session_id_type session_id;
	rand_num_type rand_num_send, rand_num_recv;

	asio::io_service &main_iosrv, &misc_iosrv;
	socket_ptr socket;

	std::unique_ptr<char[]> read_msg_buffer;
	const size_t msg_buffer_size = 0x4000;

	struct write_task {
		write_task() {};
		write_task(const std::string& _data, int _priority, write_callback&& _callback) :data(_data), callback(_callback) { priority = _priority; }
		write_task(std::string&& _data, int _priority, write_callback&& _callback) :data(_data), callback(_callback) { priority = _priority; }
		std::string data;
		write_callback callback;
		int priority;
	};
	typedef std::list<write_task> write_que_tp;
	write_que_tp write_que;

	volatile bool exiting = false;
};

class server_interface
{
public:
	virtual void on_data(user_id_type id, const std::string &data) = 0;

	virtual void on_join(user_id_type id) = 0;
	virtual void on_leave(user_id_type id) = 0;

	virtual void on_unknown_key(user_id_type id, const std::string& key) = 0;

	virtual bool new_rand_port(port_type &port) = 0;
	virtual void free_rand_port(port_type port) = 0;
};

class server
{
public:
	server(asio::io_service& _main_io_service,
		asio::io_service& _misc_io_service,
		server_interface& _inter,
		asio::ip::tcp::endpoint _local_endpoint
		)
		: main_io_service(_main_io_service),
		misc_io_service(_misc_io_service),
		acceptor(main_io_service, _local_endpoint),
		resolver(main_io_service),
		inter(_inter)
	{
		std::srand(static_cast<unsigned int>(std::time(NULL)));
		read_data();
		start();
	}

	server(asio::io_service& _main_io_service,
		asio::io_service& _misc_io_service,
		server_interface& _inter
		)
		: main_io_service(_main_io_service),
		misc_io_service(_misc_io_service),
		acceptor(main_io_service),
		resolver(main_io_service),
		inter(_inter)
	{
		std::srand(static_cast<unsigned int>(std::time(NULL)));
		read_data();
	}

	~server()
	{
		closing = true;
		acceptor.close();
		pre_sessions.clear();
		for (const auto& pair : sessions) pair.second->shutdown();
		sessions.clear();
		write_data();
	}

	void on_data(user_id_type id, std::shared_ptr<std::string> data);

	bool send_data(user_id_type id, const std::string& data, int priority);
	bool send_data(user_id_type id, const std::string& data, int priority, const std::string& message);
	bool send_data(user_id_type id, const std::string& data, int priority, session::write_callback &&callback);

	void pre_session_over(std::shared_ptr<pre_session> _pre, bool successful = false);
	void join(const session_ptr &_user);
	void leave(user_id_type id);

	void connect(const std::string &addr, port_type remote_port);
	void connect(unsigned long addr, port_type remote_port);
	void disconnect(user_id_type id);

	const session_ptr& get_session(user_id_type id) const { return sessions.at(id); }
	const std::string& get_public_key() const { return e0str; }

	void check_key(user_id_type id, const std::string& key) { if (certifiedKeys.find(key) == certifiedKeys.end()) inter.on_unknown_key(id, key); }
	void certify_key(const std::string& key) { certifiedKeys.emplace(key); }
	bool check_key_connected(const std::string& key) { if (connectedKeys.find(key) == connectedKeys.end()) { connectedKeys.emplace(key); return false; } else return true; };
private:
	void start();

	void connect(const asio::ip::tcp::endpoint &remote_endpoint);
	void connect(const asio::ip::tcp::resolver::query &query);

	void read_data();
	void write_data();

	asio::io_service &main_io_service, &misc_io_service;
	asio::ip::tcp::acceptor acceptor;
	asio::ip::tcp::resolver resolver;

	std::string e0str;
	std::unordered_set<std::string> certifiedKeys;
	std::unordered_set<std::string> connectedKeys;

	std::unordered_set<std::shared_ptr<pre_session>> pre_sessions;
	session_list_type sessions;
	user_id_type nextID = 0;

	server_interface &inter;
	volatile bool closing = false;
};

#endif
