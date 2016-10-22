#pragma once

typedef std::unordered_map<std::string, std::string> config_table_tp;
const std::string server_uname = "Server";

class plugin_error :public std::runtime_error
{
public:
	plugin_error() :std::runtime_error("Internal plugin error") {};
	plugin_error(const char* err) :std::runtime_error(err) {};
};

class plugin_interface
{
public:
	virtual bool get_id_by_name(const std::string& name, user_id_type& id) = 0;
	virtual void broadcast_msg(const std::string& msg) = 0;
	virtual void send_msg(user_id_type id, const std::string& msg) = 0;
	virtual void send_image(user_id_type id, const std::string& path) = 0;
	virtual void send_data(user_id_type id, const std::string& data) = 0;
	virtual void send_data(user_id_type id, const std::string& data, std::function<void()>&& callback) = 0;
	virtual void send_data(user_id_type id, std::string&& data) { send_data(id, data); };
	virtual void send_data(user_id_type id, std::string&& data, std::function<void()>&& callback) { send_data(id, data, std::move(callback)); };
};

class msg_server_plugin
{
public:
	enum user_type { GUEST, USER, ADMIN, CONSOLE };

	msg_server_plugin(plugin_interface& _inter)
		:inter(_inter)
	{}

	virtual void init(const config_table_tp& config_items) = 0;
	virtual void on_new_user(const std::string& name) = 0;
	virtual void on_del_user(const std::string& name) = 0;
	virtual void on_msg(const std::string& name, const std::string& msg) = 0;
	virtual void on_cmd(const std::string& name, user_type type, const std::string& cmd, const std::string& arg) = 0;
	virtual void on_img(const std::string& name, const char *data, size_t data_size) = 0;
	virtual void on_file_h(const std::string& name, const char *data, size_t data_size) = 0;
	virtual void on_file_b(const std::string& name, const char *data, size_t data_size) = 0;
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
	virtual void on_cmd(const std::string& name, user_type type, const std::string& cmd, const std::string& arg) {};
	virtual void on_img(const std::string& name, const char *data, size_t data_size);
	virtual void on_file_h(const std::string& name, const char *data, size_t data_size) {};
	virtual void on_file_b(const std::string& name, const char *data, size_t data_size) {};
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

	typedef size_t record_tp;
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
	virtual void on_cmd(const std::string& name, user_type type, const std::string& cmd, const std::string& arg);
	virtual void on_img(const std::string& name, const char *data, size_t data_size) {};
	virtual void on_file_h(const std::string& name, const char *data, size_t data_size) {};
	virtual void on_file_b(const std::string& name, const char *data, size_t data_size) {};
	virtual void on_exit() {};
private:
	bool load_config(const config_table_tp& config_items);

	bool enabled = false;
	fs::path mails_path;
};

class file_storage :public msg_server_plugin
{
private:
	static constexpr int file_block_size = 0x80000;

	struct file_info
	{
		std::string file_name, upload_user;
	};

	struct send_task
	{
		send_task(user_id_type _uID, const std::string& _file_name, const fs::path& path)
			:file_name(_file_name), uID(_uID),
			fin(path.string(), std::ios_base::in | std::ios_base::binary),
			buffer(std::make_unique<char[]>(file_block_size))
		{}

		user_id_type uID;
		std::string file_name;
		std::ifstream fin;
		data_size_type block_count = 1, block_count_all;

		std::unique_ptr<char[]> buffer;
	};

	struct recv_task
	{
		recv_task(const fs::path& path)
			:fout(path.string(), std::ios_base::out | std::ios_base::binary)
		{}

		file_info info;
		std::ofstream fout;
		data_size_type block_count = 1, block_count_all;
		CryptoPP::SHA1 hasher;
	};

	const char *data_file_name = "file_logger.dat";
	typedef std::unordered_map<std::string, file_info> hashmap_tp;
	typedef std::unordered_map<user_id_type, send_task> send_tasks_tp;
	typedef std::unordered_map<std::string, recv_task> recv_tasks_tp;
public:
	file_storage(plugin_interface& _inter)
		:msg_server_plugin(_inter)
	{}

	virtual void init(const config_table_tp& config_items);
	virtual void on_new_user(const std::string& name) {};
	virtual void on_del_user(const std::string& name) {};
	virtual void on_msg(const std::string& name, const std::string& msg) {};
	virtual void on_cmd(const std::string& name, user_type type, const std::string& cmd, const std::string& arg);
	virtual void on_img(const std::string& name, const char *data, size_t data_size) {};
	virtual void on_file_h(const std::string& name, const char *data, size_t data_size);
	virtual void on_file_b(const std::string& name, const char *data, size_t data_size);
	virtual void on_exit() { if (!enabled) return; save_data(); iosrv_work.reset(); iosrv.stop(); while (!stopped); };
private:
	bool load_config(const config_table_tp& config_items);
	void load_data();
	void save_data();

	void start(user_id_type uID, const std::string& hash);
	void send_header(send_task &task);
	void stop(user_id_type uID);
	void write(user_id_type uID);

	bool enabled = false;
	volatile bool stopped = false;
	fs::path files_path;

	send_tasks_tp send_tasks;
	recv_tasks_tp recv_tasks;
	hashmap_tp hash_map;
	asio::io_service iosrv;
	std::shared_ptr<asio::io_service::work> iosrv_work;
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
	virtual void on_cmd(const std::string& name, user_type type, const std::string& cmd, const std::string& arg) { for (const plugin_ptr &ptr : plugins) ptr->on_cmd(name, type, cmd, arg); }
	virtual void on_img(const std::string& name, const char *data, size_t data_size) { for (const plugin_ptr &ptr : plugins) ptr->on_img(name, data, data_size); };
	virtual void on_file_h(const std::string& name, const char *data, size_t data_size) { for (const plugin_ptr &ptr : plugins) ptr->on_file_h(name, data, data_size); };
	virtual void on_file_b(const std::string& name, const char *data, size_t data_size) { for (const plugin_ptr &ptr : plugins) ptr->on_file_b(name, data, data_size); };
	virtual void on_exit() { for (const plugin_ptr &ptr : plugins) ptr->on_exit(); };

	template <typename _Ty> void new_plugin() { plugins.emplace(std::make_unique<_Ty>(inter)); };
private:
	std::unordered_set<plugin_ptr> plugins;
};
