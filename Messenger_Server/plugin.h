#pragma once

typedef std::unordered_map<std::string, std::string> config_table_tp;

class msg_server_plugin
{
public:
	virtual void init(const config_table_tp &config_items) = 0;
	virtual void on_new_user(const std::string &name) = 0;
	virtual void on_del_user(const std::string &name) = 0;
	virtual void on_msg(const std::string &name, const std::string &msg) = 0;
	virtual void on_img(const std::string &name, const char *data, size_t data_size) = 0;
};

class msg_logger :public msg_server_plugin
{
public:
	virtual void init(const config_table_tp &config_items);
	virtual void on_new_user(const std::string &name) {};
	virtual void on_del_user(const std::string &name) {};
	virtual void on_msg(const std::string &name, const std::string &msg);
	virtual void on_img(const std::string &name, const char *data, size_t data_size);
private:
	bool load_config(const config_table_tp &config_items);

	const char *log_file_name = "log.md";
	const char *img_path_name = "images";

	bool enabled = false;
	std::ofstream log_stream;
	fs::path log_path;
};

class plugin_manager :public msg_server_plugin
{
public:
	typedef std::unique_ptr<msg_server_plugin> plugin_ptr;

	virtual void init(const config_table_tp &config_items) { for (const plugin_ptr &ptr : plugins) ptr->init(config_items); };
	virtual void on_new_user(const std::string &name) { for (const plugin_ptr &ptr : plugins) ptr->on_new_user(name); };
	virtual void on_del_user(const std::string &name) { for (const plugin_ptr &ptr : plugins) ptr->on_del_user(name); };
	virtual void on_msg(const std::string &name, const std::string &msg) { for (const plugin_ptr &ptr : plugins) ptr->on_msg(name, msg); };
	virtual void on_img(const std::string &name, const char *data, size_t data_size) { for (const plugin_ptr &ptr : plugins) ptr->on_img(name, data, data_size); };

	void new_plugin(plugin_ptr &&ptr) { plugins.emplace(std::move(ptr)); };
private:
	std::unordered_set<plugin_ptr> plugins;
};
