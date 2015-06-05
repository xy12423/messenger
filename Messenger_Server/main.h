#pragma once

#ifndef _H_MAIN
#define _H_MAIN

class server;
typedef std::deque<std::string> chat_message_queue;

class user : public std::enable_shared_from_this<user>
{
public:
	user(server *_srv, net::ip::tcp::socket _socket)
		: socket(std::move(_socket))
	{
		lock = NULL; blockLast = -1; srv = _srv;
	}

	void start();
	void send(const std::string& msg);

private:
	void stage1();
	void stage2();
	void read_header();
	void read_message_header();
	void read_body(size_t size);
	void write();

	int uID;
	net::ip::address addr;
	net::ip::tcp::socket socket;
	std::mutex *lock;
	CryptoPP::ECIES<CryptoPP::ECP>::Encryptor e1;

	std::string recvFile;
	int blockLast;

	std::string read_msg;
	chat_message_queue write_msgs;

	server *srv;
};
typedef std::unordered_set<std::shared_ptr<user>> userList;

class server
{
public:
	server(boost::asio::io_service& io_service,
		const net::ip::tcp::endpoint& endpoint)
		: acceptor(io_service, endpoint),
		socket(io_service)
	{
		accept();
	}
private:
	void accept();
	void leave();

	net::ip::tcp::acceptor acceptor;
	net::ip::tcp::socket socket;

	userList users;
	int nextID = 0;
};

void insLen(std::string &data);
std::string num2str(long long n);

#endif