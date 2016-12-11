#pragma once

#ifndef _H_CRYP_MAN
#define _H_CRYP_MAN

namespace crypto
{
	typedef uint32_t id_type;

	typedef std::function<void(bool, const std::string&)> crypto_callback;

	enum task_type { ENC = 0x1, DEC = 0x2 };

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
		void enc_finished() { busy_flag &= (~ENC); if (exiting) enc_task_que.clear(); else enc_task_que.pop_front(); }
		void dec_finished() { busy_flag &= (~DEC); if (exiting) dec_task_que.clear(); else dec_task_que.pop_front(); }
		bool available(task_type type) { return (busy_flag & type) == 0 && !exiting; }
		void set_busy(task_type type) { busy_flag |= type; }
		void do_one(task_type type) { if (type == ENC) do_enc(); else do_dec(); }

		void stop();

		virtual void do_enc() = 0;
		virtual void do_dec() = 0;
	protected:
		std::list<task> enc_task_que, dec_task_que;
	private:
		server &srv;
		asio::io_service& iosrv;
		id_type id;

		uint16_t busy_flag = 0;
		bool exiting = false;
	};
	typedef std::shared_ptr<session> session_ptr;

	class server
	{
	public:
		server(asio::io_service& _iosrv, int worker_count);

		template <typename _Ty1, typename... _Ty2>
		_Ty1& new_session(_Ty2&&... val) {
			id_type id = next_id;
			next_id++;
			return dynamic_cast<_Ty1&>(*sessions.emplace(id, std::make_shared<_Ty1>(*this, iosrv, id, std::forward<_Ty2>(val)...)).first->second);
		};
		void del_session(id_type id);
		void new_task(id_type id, task_type type);

		void stop();
	private:
		typedef std::list<std::pair<id_type, task_type>> task_list_tp;

		void work(id_type id);

		id_type next_id = 0;
		asio::io_service& iosrv;
		std::unordered_map<id_type, std::unique_ptr<worker>> workers;
		std::unordered_map<id_type, session_ptr> sessions;
		std::list<std::pair<id_type, task_type>> tasks;

		bool stopping = false;
	};
}

#endif
