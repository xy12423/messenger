#pragma once

#ifndef _H_CRYP_MAN
#define _H_CRYP_MAN

namespace crypto
{
	typedef uint32_t id_type;

	typedef std::function<void(bool, const std::string&)> crypto_callback;

	enum task_type { ENC = 0x1, DEC = 0x2, MISC = 0x4 };

	struct worker
	{
		worker();
		worker(const worker&) = delete;
		~worker() { stop(); }

		asio::io_service iosrv;
		std::shared_ptr<asio::io_service::work> iosrv_work;

		bool working = false;
		volatile bool stopped = false;

		void stop() { iosrv_work.reset(); while (!stopped); }
	};

	struct task
	{
		task(std::string& _data, crypto_callback&& _callback) :data(_data), callback(std::move(_callback)) {}

		id_type id;
		std::string &data;
		crypto_callback callback;
	};

	class server;

	class session :public std::enable_shared_from_this<session>
	{
	public:
		session(server& _srv, asio::io_service& _iosrv, id_type _id) :srv(_srv), iosrv(_iosrv), id(_id) {};

		id_type get_id() const { return id; }

		void enc(std::string& data, crypto_callback&& _callback);
		void dec(std::string& data, crypto_callback&& _callback);
		void misc(crypto_callback&& _callback);

		void stop();

		virtual void do_enc(task&) = 0;
		virtual void do_dec(task&) = 0;
		virtual void do_misc(task& t) { t.callback(true, t.data); }
	private:
		server &srv;
		asio::io_service& iosrv;
		id_type id;

		std::string empty_string;
	};
	typedef std::shared_ptr<session> session_ptr;

	class server
	{
	private:
		struct session_data
		{
			void enc_finished() { busy_flag &= (~ENC); if (exiting) enc_task_que.clear(); else enc_task_que.pop_front(); }
			void dec_finished() { busy_flag &= (~DEC); if (exiting) dec_task_que.clear(); else dec_task_que.pop_front(); }
			void misc_finished() { busy_flag &= (~MISC); if (exiting) misc_task_que.clear(); else misc_task_que.pop_front(); }
			bool available(task_type type) { return (busy_flag & type) == 0 && !exiting; }
			void set_busy(task_type type) { busy_flag |= type; }

			std::list<task> enc_task_que, dec_task_que, misc_task_que;
			uint16_t busy_flag = 0;
			bool exiting = false;
		};
		typedef std::shared_ptr<session_data> session_data_ptr;
	public:
		server(asio::io_service& _iosrv, int worker_count);

		template <typename _Ty1, typename... _Ty2>
		std::shared_ptr<_Ty1> new_session(_Ty2&&... val) {
			id_type id = next_id;
			next_id++;
			sessions_data.emplace(id, std::make_shared<session_data>());
			return std::static_pointer_cast<_Ty1>(sessions.emplace(id, std::make_shared<_Ty1>(*this, iosrv, id, std::forward<_Ty2>(val)...)).first->second);
		};
		void del_session(id_type id);
		void new_task(id_type id, task_type type, task&& task);

		const std::thread::id& get_thread_id() { return iosrv_thread_id; }

		void stop();
	private:
		typedef std::list<std::pair<id_type, task_type>> task_list_tp;

		void work(id_type id);

		id_type next_id = 0;
		asio::io_service& iosrv;
		std::unordered_map<id_type, std::unique_ptr<worker>> workers;
		std::unordered_map<id_type, session_ptr> sessions;
		std::unordered_map<id_type, session_data_ptr> sessions_data;
		task_list_tp tasks;

		std::thread::id iosrv_thread_id;

		bool stopping = false;
	};
}

#endif
