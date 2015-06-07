#pragma once

#ifndef _H_MAIN
#define _H_MAIN

class server;
typedef std::deque<std::string> chat_message_queue;

class pre_session : public std::enable_shared_from_this < pre_session >
{
public:
	pre_session(boost::asio::io_service& io_service,
		const net::ip::tcp::endpoint& endpoint, server *_srv)
		: io_service(io_service),
		acceptor(io_service, endpoint)
	{
		srv = _srv;
		start();
	}

	void start();
private:
	void stage2(boost::shared_ptr<net::ip::tcp::socket> socket, error_code ec);

	boost::asio::io_service &io_service;
	net::ip::tcp::acceptor acceptor;

	server *srv;
};

class session : public std::enable_shared_from_this<session>
{
public:
	session(server *_srv, net::ip::tcp::socket _socket)
		: socket(std::move(_socket))
	{
		lock = NULL; blockLast = -1; srv = _srv; msg_len = 0;
		read_msg = new char[msg_size];
	}

	void start();
	void send(const std::string& msg);

private:
	void read_header();
	void read_message_header();
	void read_file_header();
	void read_fileblock_header();
	void read_message(size_t size);
	void read_fileblock();
	void write();

	int uID;
	net::ip::address addr;
	net::ip::tcp::socket socket;
	std::mutex *lock;
	CryptoPP::ECIES<CryptoPP::ECP>::Encryptor e1;

	std::string recvFile;
	int blockLast;

	char *read_msg;
	const int msg_size = 0x4000;
	size_t msg_len;
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

	void send(std::shared_ptr<session> from, const std::string& msg);
	void leave(std::shared_ptr<session> _user);
private:
	void start();
	void accept(boost::shared_ptr<net::ip::tcp::socket> socket, error_code ec);
	void stage1();

	boost::asio::io_service &io_service;
	net::ip::tcp::acceptor acceptor;

	userList users;
	std::unordered_set<std::shared_ptr<pre_session>> pre_sessions;
	int nextID = 0;
};

void insLen(std::string &data);
std::string num2str(long long n);

#endif