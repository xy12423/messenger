#pragma once

#ifndef _H_MAIN
#define _H_MAIN

enum modes { EASY, NORMAL, HARD };
constexpr int server_uid = -1;
constexpr port_type portConnect = 4826;

class cli_server;

class cli_plugin_interface :public plugin_interface
{
public:
	cli_plugin_interface(cli_server* _srv) :srv(_srv) {}

	virtual bool get_id_by_name(const std::string& name, user_id_type& id) override;
	virtual feature_flag_type get_feature(user_id_type id) override;

	virtual void broadcast_msg(const std::string& msg) override;
	virtual void send_msg(user_id_type id, const std::string& msg) override;
	virtual void send_msg(user_id_type id, const std::string& msg, const std::string& from) override;
	virtual void send_image(user_id_type id, const std::string& path) override;
	virtual void send_image(user_id_type id, const std::string& path, const std::string& from) override;

	virtual void send_data(user_id_type id, const std::string& data, int priority) override;
	virtual void send_data(user_id_type id, const std::string& data, int priority, std::function<void()>&& callback) override;
	virtual void send_data(user_id_type id, std::string&& data, int priority) override;
	virtual void send_data(user_id_type id, std::string&& data, int priority, std::function<void()>&& callback) override;
private:
	cli_server *srv;
};

struct user_record
{
	enum group_type { GUEST, USER, ADMIN, CONSOLE };

	user_record() { group = GUEST; }
	template <typename _Ty1, typename _Ty2>
	user_record(_Ty1&& _name, _Ty2&& _passwd, group_type _group) :
		name(std::forward<_Ty1>(_name)), passwd(std::forward<_Ty1>(_passwd)), group(_group)
	{}

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
	feature_flag_type supported = 0;

	std::string uploading_key;
};
typedef std::unordered_map<int, user_ext> user_ext_list;

class cli_server_error :public std::runtime_error
{
public:
	cli_server_error() :std::runtime_error("Internal server error") {}
};

class cli_server :public msgr_proto::server
{
public:
	cli_server(asio::io_service& _main_io_service,
		asio::io_service& _misc_io_service,
		asio::ip::tcp::endpoint _local_endpoint,
		crypto::provider& _crypto_prov,
		crypto::server& _crypto_srv)
		:msgr_proto::server(_main_io_service, _misc_io_service, _local_endpoint, _crypto_prov, _crypto_srv),
		i_plugin(this),
		m_plugin(i_plugin)
	{
		read_data();
		user_exts[server_uid].name = user_exts[server_uid].addr = server_uname;
		user_exts[server_uid].current_stage = user_ext::LOGGED_IN;
	}
	~cli_server() {
		write_data();
	}

	virtual bool new_rand_port(port_type& port);
	virtual void free_rand_port(port_type port) { ports.push_back(port); };

	//Server sends msg
	void send_msg(user_id_type dst, const std::string& msg) { return send_msg(dst, msg, user_exts.at(dst).supported, server_uname); }
	//src sends msg
	void send_msg(user_id_type dst, const std::string& msg, const std::string& src) { return send_msg(dst, msg, user_exts.at(dst).supported, src); }
	//Server sends msg, dst flag is given
	void send_msg(user_id_type dst, const std::string& msg, feature_flag_type flags) { return send_msg(dst, msg, flags, server_uname); }
	//src sends msg, dst flag is given
	//arg src is only appended to msg when feature_message_from is enabled
	void send_msg(user_id_type dst, const std::string& msg, feature_flag_type flags, const std::string& src);
	//src broadcasts msg
	void broadcast_msg(int src, const std::string& msg);
	//src broadcasts img
	void broadcast_img(int src, const std::string& data);
	//src broadcasts data
	void broadcast_data(int src, const std::string& data, int priority);
	void kick(user_record& user);

	bool get_id_by_name(const std::string& name, user_id_type& ret);
	feature_flag_type get_feature(user_id_type id) { return user_exts.at(id).supported; }

	void on_msg(user_id_type id, std::string& msg);
	std::string on_cmd(std::string& cmd, user_record& user);
	void on_image(user_id_type id, const std::string& data);
	void on_file_h(user_id_type id, const std::string& data);
	void on_file_b(user_id_type id, const std::string& data);
	void on_exit();

	void set_mode(modes _mode) { mode = _mode; }
	void set_static_port(port_type port) { static_port = port; };

	void init_plugin();
	template <typename T1, typename... T2>
	void add_plugin(T2&&... val) { m_plugin.new_plugin<T1>(std::forward<T2>(val)...); }

	static void read_config();
private:
	virtual void on_data(user_id_type id, const std::string& data);

	virtual void on_join(user_id_type id, const std::string&);
	virtual void on_leave(user_id_type id);

	void read_data();
	void write_data();
	void process_config();

	static constexpr uint32_t data_ver = 0x00;
	const char *data_ver_dat = "\x00\x00\x00\x00";

	int static_port = 0;
	std::list<port_type> ports;
	modes mode = EASY;

	bool display_ip = true;

	user_record_list user_records;
	user_ext_list user_exts;

	cli_plugin_interface i_plugin;
	plugin_manager m_plugin;
	key_storage user_key_storage;
};

#endif
