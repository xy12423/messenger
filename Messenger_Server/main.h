#pragma once

#ifndef _H_MAIN
#define _H_MAIN

enum modes{ EASY, NORMAL, HARD };

const port_type portConnect = 4826;

struct user_record
{
	enum group_type { GUEST, USER, ADMIN, CONSOLE };

	user_record() { group = GUEST; }
	user_record(const std::string& _name, const std::string& _passwd, group_type _group) :
		name(_name), passwd(_passwd)
	{
		group = _group;
	}

	std::string name, passwd;
	group_type group;
	bool logged_in;
	user_id_type id;
};
typedef std::unordered_map<std::string, user_record> user_record_list;

struct user_ext
{
	enum stage { LOGIN_NAME, LOGIN_PASS, LOGGED_IN };
	stage current_stage = LOGIN_NAME;

	std::string name;
	std::string addr;

	std::string uploading_key;
};
typedef std::unordered_map<int, user_ext> user_ext_list;

class cli_server_error :public std::runtime_error
{
public:
	cli_server_error() :std::runtime_error("Internal server error") {};
};

constexpr int server_uid = -1;
const char *config_file = ".config";
const char *data_file = ".data";
class cli_server :public msgr_proto::server
{
public:
	cli_server(asio::io_service& _main_io_service,
		asio::io_service& _misc_io_service,
		asio::ip::tcp::endpoint _local_endpoint,
		crypto::provider& _crypto_prov,
		crypto::server& _crypto_srv)
		:msgr_proto::server(_main_io_service, _misc_io_service, _local_endpoint, _crypto_prov, _crypto_srv)
	{
		read_data();
		user_exts[server_uid].name = user_exts[server_uid].addr = server_uname;
		user_exts[server_uid].current_stage = user_ext::LOGGED_IN;
	}
	~cli_server() {
		write_data();
	}

	virtual void on_data(user_id_type id, const std::string& data);

	virtual void on_join(user_id_type id, const std::string&);
	virtual void on_leave(user_id_type id);

	virtual bool new_rand_port(port_type& port);
	virtual void free_rand_port(port_type port) { ports.push_back(port); };

	void send_msg(user_id_type id, const std::string& msg);
	void broadcast_msg(int id, const std::string& msg);
	void broadcast_data(int id, const std::string& data, int priority);
	std::string process_command(std::string& cmd, user_record& user);

	bool get_id_by_name(const std::string& name, user_id_type& ret);

	void on_msg(user_id_type id, std::string& msg);
	void on_image(user_id_type id, const std::string& data);
	void on_file_h(user_id_type id, const std::string& data);
	void on_file_b(user_id_type id, const std::string& data);
	void on_exit();

	void set_mode(modes _mode) { mode = _mode; }
	void set_static_port(port_type port) { static_port = port; };

	static void read_config();
private:
	void read_data();
	void write_data();

	const uint32_t data_ver = 0x00;

	int static_port = -1;
	std::list<port_type> ports;

	modes mode = EASY;
	user_record_list user_records;
	user_ext_list user_exts;
};

class cli_plugin_interface :public plugin_interface
{
public:
	virtual bool get_id_by_name(const std::string& name, user_id_type& id);
	virtual void broadcast_msg(const std::string& msg);
	virtual void send_msg(user_id_type id, const std::string& msg);
	virtual void send_image(user_id_type id, const std::string& path);
	virtual void send_data(user_id_type id, const std::string& data);
	virtual void send_data(user_id_type id, const std::string& data, std::function<void()>&& callback);
	virtual void send_data(user_id_type id, std::string&& data);
	virtual void send_data(user_id_type id, std::string&& data, std::function<void()>&& callback);
};

#endif
