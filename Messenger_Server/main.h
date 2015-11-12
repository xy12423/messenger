#pragma once

#ifndef _H_MAIN
#define _H_MAIN

enum modes{ RELAY, CENTER };

const port_type portConnect = 4826;

struct user_record
{
	enum group_type{ GUEST, USER, ADMIN };

	user_record(){ group = GUEST; }
	user_record(const std::string &_name, const std::string &_passwd, group_type _group) :
		name(_name), passwd(_passwd)
	{
		group = _group;
	}

	std::string name, passwd;
	group_type group;
};
typedef std::unordered_map<std::string, user_record> user_record_list;

struct user_ext
{
	enum stage { LOGIN_NAME, LOGIN_PASS, LOGGED_IN };
	stage current_stage = LOGIN_NAME;

	std::string name;
	std::string addr;

	std::string recvFile;
	int blockLast;
};
typedef std::unordered_map<int, user_ext> user_ext_list;

class cli_server_interface :public server_interface
{
public:
	virtual void on_data(user_id_type id, const std::string &data);

	virtual void on_join(user_id_type id);
	virtual void on_leave(user_id_type id);

	virtual void on_unknown_key(user_id_type id, const std::string& key) {};

	virtual bool new_rand_port(port_type &port);
	virtual void free_rand_port(port_type port) { ports.push_back(port); };

	void broadcast_msg(user_id_type id, const std::string &msg);
	void broadcast_data(user_id_type id, const std::string &data, int priority);
	std::string process_command(std::string cmd, user_record &user);

	void set_static_port(port_type port) { static_port = port; };
private:
	int static_port = -1;
	std::list<port_type> ports;
};

#endif
