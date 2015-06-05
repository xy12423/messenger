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
		lock = NULL; blockLast = -1; srv = _srv; msg_len = 0;
		read_msg = new char[msg_size];
	}

	void start();
	void send(const std::string& msg);

private:
	void stage2();
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

	void send(std::shared_ptr<user> from, const std::string& msg);
	void leave(std::shared_ptr<user> _user);
private:
	void accept();
	void stage1();

	net::ip::tcp::acceptor acceptor;
	net::ip::tcp::endpoint ep;
	net::ip::tcp::socket socket;

	userList users;
	int nextID = 0;
};

void insLen(std::string &data);
std::string num2str(long long n);

#endif