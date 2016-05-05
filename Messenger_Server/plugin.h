#pragma once

typedef std::unordered_map<std::string, std::string> config_table_tp;
const std::string server_uname = "Server";

class plugin_interface
{
public:
	virtual bool get_id_by_name(const std::string& name, user_id_type& id) = 0;
	virtual void broadcast_msg(const std::string& msg) = 0;
	virtual void send_msg(user_id_type id, const std::string& msg) = 0;
	virtual void send_image(user_id_type id, const std::string& path) = 0;
};

class msg_server_plugin
{
public:
	msg_server_plugin(plugin_interface& _inter)
		:inter(_inter)
	{}

	virtual void init(const config_table_tp& config_items) = 0;
	virtual void on_new_user(const std::string& name) = 0;
	virtual void on_del_user(const std::string& name) = 0;
	virtual void on_msg(const std::string& name, const std::string& msg) = 0;
	virtual void on_cmd(const std::string& name, const std::string& cmd, const std::string& arg) = 0;
	virtual void on_img(const std::string& name, const char *data, size_t data_size) = 0;
	virtual void on_exit() = 0;
protected:
	plugin_interface &inter;
};

class msg_logger :public msg_server_plugin
{
public:
	msg_logger(plugin_interface& _inter);

	virtual void init(const config_table_tp& config_items);
	virtual void on_new_user(const std::string& name);
	virtual void on_del_user(const std::string& name);
	virtual void on_msg(const std::string& name, const std::string& msg);
	virtual void on_cmd(const std::string& name, const std::string& cmd, const std::string& arg) {};
	virtual void on_img(const std::string& name, const char *data, size_t data_size);
	virtual void on_exit() {};
private:
	enum offline_msg_lvls {
		OFF, NOIMG, ON
	};

	bool load_config(const config_table_tp& config_items);
	void read_data();
	void write_data();

	const char *log_file_name = "log.md";
	const char *data_file_name = "msg_logger.dat";
	const char *img_path_name = "images";

	bool enabled = false;
	offline_msg_lvls offline_msg_lvl = OFF;
	std::fstream log_fstream;
	std::ostream log_stream;
	fs::path log_path;

	typedef uint32_t record_tp;
	typedef std::unordered_map<std::string, record_tp> record_list;
	record_list records;
};

class server_mail :public msg_server_plugin
{
public:
	server_mail(plugin_interface& _inter)
		:msg_server_plugin(_inter)
	{}

	virtual void init(const config_table_tp& config_items);
	virtual void on_new_user(const std::string& name);
	virtual void on_del_user(const std::string& name) {};
	virtual void on_msg(const std::string& name, const std::string& msg) {};
	virtual void on_cmd(const std::string& name, const std::string& cmd, const std::string& arg);
	virtual void on_img(const std::string& name, const char *data, size_t data_size) {};
	virtual void on_exit() {};
private:
	bool load_config(const config_table_tp& config_items);

	bool enabled = false;
	fs::path mails_path;
};

class plugin_manager :public msg_server_plugin
{
public:
	plugin_manager(plugin_interface& _inter)
		:msg_server_plugin(_inter)
	{}

	typedef std::unique_ptr<msg_server_plugin> plugin_ptr;

	virtual void init(const config_table_tp& config_items) { for (const plugin_ptr& ptr : plugins) ptr->init(config_items); };
	virtual void on_new_user(const std::string& name) { for (const plugin_ptr& ptr : plugins) ptr->on_new_user(name); };
	virtual void on_del_user(const std::string& name) { for (const plugin_ptr& ptr : plugins) ptr->on_del_user(name); };
	virtual void on_msg(const std::string& name, const std::string& msg) { for (const plugin_ptr &ptr : plugins) ptr->on_msg(name, msg); };
	virtual void on_cmd(const std::string& name, const std::string& cmd, const std::string& arg) { for (const plugin_ptr &ptr : plugins) ptr->on_cmd(name, cmd, arg); }
	virtual void on_img(const std::string& name, const char *data, size_t data_size) { for (const plugin_ptr &ptr : plugins) ptr->on_img(name, data, data_size); };
	virtual void on_exit() { for (const plugin_ptr &ptr : plugins) ptr->on_exit(); };

	template <typename _Ty> void new_plugin() { plugins.emplace(std::make_unique<_Ty>(inter)); };
private:
	std::unordered_set<plugin_ptr> plugins;
};
