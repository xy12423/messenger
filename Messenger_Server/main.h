#pragma once

#ifndef _H_MAIN
#define _H_MAIN

enum modes{ RELAY, CENTER };

struct user_log
{
	enum group_type{ GUEST, USER, ADMIN };

	user_log(){ group = GUEST; }
	user_log(const std::string &_name, const std::string &_passwd, group_type _group) :
		name(_name), passwd(_passwd)
	{
		group = _group;
	}

	std::string name, passwd;
	group_type group;
};
typedef std::unordered_map<std::string, user_log> user_log_list;

struct user_ext_data
{
	enum stage { LOGIN_NAME, LOGIN_PASS, LOGGED_IN };
	stage current_stage = LOGIN_NAME;

	std::string name;
	std::string addr;

	std::string recvFile;
	int blockLast;
};
typedef std::unordered_map<int, user_ext_data> user_ext_list;

class cli_server_interface :public server_interface
{
public:
	virtual void on_data(id_type id, const std::string &data);

	virtual void on_join(id_type id);
	virtual void on_leave(id_type id);

	virtual void on_unknown_key(id_type id, const std::string& key) {};

	void broadcast_msg(id_type id, const std::string &msg);
	void broadcast_data(id_type id, const std::string &data, int priority);
	void process_command(std::string cmd, user_log::group_type type);
};

#endif
