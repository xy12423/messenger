#pragma once

#ifndef _H_MAIN
#define _H_MAIN

class server;
typedef std::deque<std::string> chat_message_queue;
typedef std::shared_ptr<net::ip::tcp::socket> socket_ptr;

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
	session(server *_srv, const socket_ptr &_socket)
		: socket(_socket)
	{
		blockLast = -1; srv = _srv;
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

	std::string recvFile;
	int blockLast;

	char *read_msg_buffer;
	const size_t msg_buffer_size = 0x4000;
	chat_message_queue write_msgs;

	server *srv;
};
typedef std::unordered_set<std::shared_ptr<session>> userList;

class server
{
public:
	server(boost::asio::io_service& io_service,
		const net::ip::tcp::endpoint& endpoint)
		: io_service(io_service),
		acceptor(io_service, endpoint)
	{
		start();
	}

	void send_message(std::shared_ptr<session> from, const std::string& msg);
	void send_fileheader(std::shared_ptr<session> from, const std::string& data);
	void send_fileblock(std::shared_ptr<session> from, const std::string& block);
	void pre_session_over(std::shared_ptr<pre_session> _pre){ pre_sessions.erase(_pre); }
	void join(std::shared_ptr<session> _user){ std::cout << "New user " << _user->get_address() << std::endl; users.emplace(_user); }
	void leave(std::shared_ptr<session> _user){ std::cout << "Delete user " << _user->get_address() << std::endl; users.erase(_user); };
private:
	void start();
	void accept(boost::system::error_code ec);

	boost::asio::io_service &io_service;
	socket_ptr accepting;
	net::ip::tcp::acceptor acceptor;

	userList users;
	std::unordered_set<std::shared_ptr<pre_session>> pre_sessions;
	int nextID = 0;
};

#endif