#pragma once

#ifndef _H_MAIN
#define _H_MAIN

enum modes{ RELAY, CENTER };

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

	std::string addr;

	std::string recvFile;
	int blockLast;
};
typedef std::unordered_map<id_type, user> user_list;

class cli_server_interface :public server_interface
{
public:
	virtual void on_data(id_type id, const std::string &data);

	virtual void on_join(id_type id);
	virtual void on_leave(id_type id);

	virtual void on_unknown_key(id_type id, const std::string& key) {};

	void process_command(const std::string &cmd, user::group_type type);
};

class iosrv_thread
{
public:
	iosrv_thread(net::io_service& _iosrv)
		:iosrv(_iosrv), run_thread(&iosrv_thread::run, this)
	{
		iosrv_work = std::make_shared<net::io_service::work>(iosrv);
		run_thread.detach();
	}

	void stop() { iosrv_work.reset(); iosrv.stop(); }
private:
	net::io_service& iosrv;
	std::shared_ptr<net::io_service::work> iosrv_work;

	std::thread run_thread;

	void run() { iosrv.run(); }
};

#endif