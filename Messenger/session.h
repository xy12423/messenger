#pragma once

#ifndef _H_SESSION
#define _H_SESSION

typedef uint16_t key_length_type;
typedef uint32_t data_length_type;

typedef uint16_t port_type;

typedef int user_id_type;
typedef uint64_t session_id_type;

typedef std::shared_ptr<net::ip::tcp::socket> socket_ptr;

void insLen(std::string &data);

class server;

class pre_session : public std::enable_shared_from_this<pre_session>
{
public:
	pre_session(server *_srv, port_type _local_port, net::io_service &main_io_srv, net::io_service &misc_io_srv)
		:main_io_service(main_io_srv),
		misc_io_service(misc_io_srv),
		socket(std::make_shared<net::ip::tcp::socket>(main_io_service))
	{
		srv = _srv;
		local_port = _local_port;
	}

	~pre_session() { if (!passed) { exiting = true; socket->close(); } }

	port_type get_port() const { return local_port; }
	const std::string& get_key() const { return key_string; }

	virtual void start() = 0;
private:
	virtual void stage1() = 0;
	virtual void stage2() = 0;
	virtual void sid_packet_done() = 0;
protected:
	void read_key_header();
	void read_key();

	void read_session_id(int check_level);
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

	net::io_service &main_io_service, &misc_io_service;
	socket_ptr socket;

	server *srv;
	port_type local_port;
	volatile bool exiting = false, passed = false;
};

class pre_session_s :public pre_session
{
public:
	pre_session_s(port_type local_port, const net::ip::tcp::endpoint& endpoint, server *_srv, net::io_service &io_srv, net::io_service &misc_io_srv)
		:pre_session(_srv, local_port, io_srv, misc_io_srv),
		acceptor(main_io_service, endpoint)
	{}

	virtual void start();
private:
	virtual void stage1();
	virtual void stage2();
	virtual void sid_packet_done();

	net::ip::tcp::acceptor acceptor;
};

class pre_session_c :public pre_session
{
public:
	pre_session_c(port_type local_port, const net::ip::tcp::endpoint& endpoint, server *_srv, net::io_service &io_srv, net::io_service &misc_io_srv)
		:pre_session(_srv, local_port, io_srv, misc_io_srv),
		ep(endpoint)
	{}

	virtual void start();
private:
	virtual void stage1() { read_key_header(); };
	virtual void stage2();
	virtual void sid_packet_done();

	net::ip::tcp::endpoint ep;
};

class session
{
public:
	static const int priority_sys = 30;
	static const int priority_msg = 20;
	static const int priority_plugin = 15;
	static const int priority_file = 10;

	typedef std::function<void()> write_callback;

	session(server *_srv, port_type _local_port,
		net::io_service& _main_iosrv, net::io_service& _misc_iosrv,
		socket_ptr &&_socket,
		const std::string &_key_string,
		session_id_type _session_id, rand_num_type _rand_num_send, rand_num_type _rand_num_recv)
		:srv(_srv), local_port(_local_port), main_iosrv(_main_iosrv), misc_iosrv(_misc_iosrv), socket(_socket), key_string(_key_string),
		session_id(_session_id), rand_num_send(_rand_num_send), rand_num_recv(_rand_num_recv)
	{
		read_msg_buffer = std::make_unique<char[]>(msg_buffer_size);

		CryptoPP::StringSource keySource(key_string, true);
		e1.AccessPublicKey().Load(keySource);
	}

	~session()
	{
		exiting = true;
		socket->close();
	}

	void start();
	void send(const std::string& data, int priority, write_callback &&callback);
	void stop_file_transfer();

	void shutdown() { socket->shutdown(socket->shutdown_both); }

	std::string get_address() const { return socket->remote_endpoint().address().to_string(); }
	unsigned long get_address_ulong() const { return socket->remote_endpoint().address().to_v4().to_ulong(); }
	port_type get_port() const { return local_port; }
	const std::string& get_key() const { return key_string; }
	session_id_type get_session_id() const { return session_id; };
	rand_num_type get_rand_num_recv() { rand_num_recv++; return rand_num_recv; };

	friend class pre_session_s;
	friend class pre_session_c;
private:
	void read_header();
	void read_data(size_t sizeLast, std::shared_ptr<std::string> buf);
	void write();

	net::io_service &main_iosrv, &misc_iosrv;
	socket_ptr socket;

	std::string key_string;
	CryptoPP::ECIES<CryptoPP::ECP>::Encryptor e1;

	session_id_type session_id;
	rand_num_type rand_num_send, rand_num_recv;

	user_id_type id;

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
	bool writing;

	server *srv;
	port_type local_port;
	volatile bool exiting = false;
};
typedef std::shared_ptr<session> session_ptr;
typedef std::unordered_map<user_id_type, session_ptr> sessionList;

class server_interface
{
public:
	virtual void on_data(user_id_type id, const std::string &data) = 0;

	virtual void on_join(user_id_type id) = 0;
	virtual void on_leave(user_id_type id) = 0;

	virtual void on_unknown_key(user_id_type id, const std::string& key) = 0;
};

class server
{
public:
	server(net::io_service& _main_io_service,
		net::io_service& _misc_io_service,
		server_interface *_inter,
		net::ip::tcp::endpoint _local_endpoint,
		port_type _local_port_connect,
		std::list<port_type> &&_local_ports
		)
		: main_io_service(_main_io_service),
		misc_io_service(_misc_io_service),
		acceptor(main_io_service, _local_endpoint),
		local_port_connect(_local_port_connect),
		inter(_inter),
		local_ports(_local_ports)
	{
		std::srand(static_cast<unsigned int>(std::time(NULL)));
		read_data();
		start();
	}

	~server()
	{
		closing = true;
		acceptor.close();
		accepting->close();
		pre_sessions.clear();
		sessions.clear();
		write_data();
	}

	void on_data(user_id_type id, std::shared_ptr<std::string> data);

	bool send_data(user_id_type id, const std::string& data, int priority);
	bool send_data(user_id_type id, const std::string& data, int priority, const std::string& message);
	bool send_data(user_id_type id, const std::string& data, int priority, session::write_callback &&callback);

	void pre_session_over(std::shared_ptr<pre_session> _pre, bool successful = false);
	user_id_type join(const session_ptr &_user);
	void leave(user_id_type id);

	void connect(const std::string &addr, port_type remote_port);
	void connect(unsigned long addr, port_type remote_port);
	void disconnect(user_id_type id);

	const session_ptr& get_session(user_id_type id) const { return sessions.at(id); }
	const std::string& get_public_key() const { return e0str; }

	void check_key(user_id_type id, const std::string& key) { if (certifiedKeys.find(key) == certifiedKeys.end()) inter->on_unknown_key(id, key); }
	void certify_key(const std::string& key) { certifiedKeys.emplace(key); }
	bool check_key_connected(const std::string& key) { if (connectedKeys.find(key) == connectedKeys.end()) { connectedKeys.emplace(key); return false; } else return true; };
private:
	void start();
	void accept(boost::system::error_code ec);

	void connect(const net::ip::address& addr, port_type remote_port);

	void read_data();
	void write_data();

	net::io_service &main_io_service, &misc_io_service;
	socket_ptr accepting;
	net::ip::tcp::acceptor acceptor;

	std::list<port_type> local_ports;
	port_type local_port_connect;

	std::string e0str;
	std::unordered_set<std::string> certifiedKeys;
	std::unordered_set<std::string> connectedKeys;

	std::unordered_set<std::shared_ptr<pre_session>> pre_sessions;
	sessionList sessions;
	user_id_type nextID = 0;

	server_interface *inter;
	volatile bool closing = false;
};

#endif
