#pragma once

#ifndef _H_MAIN
#define _H_MAIN

class server;
typedef std::deque<std::string> chat_message_queue;
typedef std::shared_ptr<net::ip::tcp::socket> socket_ptr;

enum modes{ RELAY, CENTER };
extern modes mode;

struct user
{
	enum group_type{ GUEST, USER, ADMIN };

	user(){ group = GUEST; }
	user(const std::string &_name, const std::string &_passwd, group_type _group) :
		name(_name), passwd(_passwd)
	{
		group = _group;
	}

	std::string name, passwd;
	group_type group;
};
typedef std::unordered_map<std::string, user> userList;

class pre_session : public std::enable_shared_from_this<pre_session>
{
public:
	pre_session(boost::asio::io_service& io_service,
		const net::ip::tcp::endpoint& endpoint, server *_srv)
		: io_service(io_service),
		acceptor(io_service, endpoint)
	{
		srv = _srv;
		key_buffer = NULL;
		start();
	}

	void start();
private:
	void stage1(socket_ptr socket, boost::system::error_code ec);
	void read_key_header();
	void read_key();

	unsigned short key_length;
	char *key_buffer;

	boost::asio::io_service &io_service;
	socket_ptr socket;
	net::ip::tcp::acceptor acceptor;

	server *srv;
};

class session : public std::enable_shared_from_this<session>
{
public:
	enum session_state{ INPUT_USER, INPUT_PASSWD, LOGGED_IN };

	session(server *_srv, const socket_ptr &_socket)
		: socket(_socket)
	{
		state = INPUT_USER; srv = _srv;
		read_msg_buffer = new char[msg_buffer_size];
	}

	~session()
	{
		socket->close();
	}

	void start();
	void send_message(const std::string& msg);
	void send_fileheader(const std::string& data);
	void send_fileblock(const std::string& block);
	std::string get_address(){ return socket->remote_endpoint().address().to_string(); }
	session_state get_state(){ return state; }

	friend class pre_session;
private:
	void read_header();
	void read_message_header();
	void read_fileheader_header();
	void read_fileblock_header();
	void read_message(size_t size, std::string *read_msg);
	void read_fileheader(size_t size, std::string *read_msg);
	void read_fileblock(size_t size, std::string *read_msg);
	void write();

	void process_message(const std::string &originMsg);

	socket_ptr socket;
	CryptoPP::ECIES<CryptoPP::ECP>::Encryptor e1;

	std::string user_name;
	session_state state;

	char *read_msg_buffer;
	const size_t msg_buffer_size = 0x4000;
	chat_message_queue write_msgs;

	server *srv;
};
typedef std::unordered_set<std::shared_ptr<session>> sessionList;

class server
{
public:
	server(boost::asio::io_service& io_service,
		const net::ip::tcp::endpoint& endpoint)
		: io_service(io_service),
		acceptor(io_service, endpoint)
	{
		read_config();
		start();
	}

	void send_message(std::shared_ptr<session> from, const std::string& msg);
	void send_fileheader(std::shared_ptr<session> from, const std::string& data);
	void send_fileblock(std::shared_ptr<session> from, const std::string& block);
	void pre_session_over(std::shared_ptr<pre_session> _pre){ pre_sessions.erase(_pre); }
	void join(std::shared_ptr<session> _user);
	void leave(std::shared_ptr<session> _user);

	bool login(const std::string &name, const std::string &passwd);

	user::group_type get_group(const std::string &name){ userList::iterator itr = users.find(name); if (itr != users.end()) return itr->second.group; return user::GUEST; }
	bool is_op(const std::string &name){ userList::iterator itr = users.find(name); if (itr != users.end()) return itr->second.group == user::ADMIN; return false; }

	bool process_command(std::string command, user::group_type group);
private:
	void start();
	void accept(boost::system::error_code ec);

	const char* config_file = ".config";
	void read_config();
	void write_config();

	boost::asio::io_service &io_service;
	socket_ptr accepting;
	net::ip::tcp::acceptor acceptor;

	std::unordered_set<std::shared_ptr<pre_session>> pre_sessions;
	sessionList sessions;
	userList users;
	int nextID = 0;
};

#endif