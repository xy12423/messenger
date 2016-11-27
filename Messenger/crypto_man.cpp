#include "stdafx.h"
#include "crypto_man.h"

using namespace crypto;

worker::worker()
{
	iosrv_work = std::make_shared<asio::io_service::work>(iosrv);
	std::thread thread([this]() {
		while (iosrv_work)
		{
			try
			{
				iosrv.run();
			}
			catch (...) {}
		}
		stopped = true;
	});
	thread.detach();
}

void session::enc(std::string& data, crypto_callback&& _callback)
{
	std::shared_ptr<task> new_task = std::make_shared<task>(data, std::move(_callback));
	iosrv.post([this, new_task]() {
		enc_task_que.push_back(std::move(*new_task));
		srv.new_task(id, ENC);
	});
}

void session::dec(std::string& data, crypto_callback&& _callback)
{
	std::shared_ptr<task> new_task = std::make_shared<task>(data, std::move(_callback));
	iosrv.post([this, new_task]() {
		dec_task_que.push_back(std::move(*new_task));
		srv.new_task(id, DEC);
	});
}

void session::stop()
{
	iosrv.post([this]() {
		stopping = true;
		srv.del_session(id);
	});
}

server::server(asio::io_service& _iosrv, int worker_count)
	:iosrv(_iosrv)
{
	for (int i = 0; i < worker_count; i++)
		workers.emplace(i, std::make_unique<worker>());
}

void server::stop()
{
	stopping = true;
	for (std::unordered_map<id_type, std::unique_ptr<worker>>::iterator itr = workers.begin(), itr_end = workers.end(); itr != itr_end; itr++)
		itr->second->stop();
}

void server::del_session(id_type id)
{
	std::unordered_map<id_type, session_ptr>::iterator itr = sessions.find(id);
	if (itr == sessions.end())
		return;

	task_list_tp::iterator task_itr = tasks.begin(), task_itr_end = tasks.end();
	while (task_itr != task_itr_end)
	{
		if (task_itr->first == id)
			task_itr = tasks.erase(task_itr);
		else
			task_itr++;
	}

	sessions.erase(itr);
}

void server::new_task(id_type id, task_type type)
{
	session_ptr &self = sessions.at(id);
	tasks.emplace_back(id, type);
	if (!self->available(type))
		return;

	for (const std::unordered_map<id_type, std::unique_ptr<worker>>::value_type& pair : workers)
		if (!pair.second->working)
			run_task(pair.first);
}

void server::run_task(id_type id)
{
	if (stopping)
		return;
	worker &w = *workers.at(id);
	
	task_list_tp::iterator task_itr = tasks.begin(), task_itr_end = tasks.end();
	for (; task_itr != task_itr_end; task_itr++)
		if (sessions.at(task_itr->first)->available(task_itr->second))
			break;
	if (task_itr == task_itr_end)
		return;
	session_ptr self = sessions.at(task_itr->first);
	task_type type = task_itr->second;
	tasks.erase(task_itr);
	self->set_busy(type);
	w.working = true;

	w.iosrv.post([this, self, id, type]() {
		self->do_one(type);

		iosrv.post([this, self, id, type]() {
			try
			{
				if (type == ENC)
					self->enc_finished();
				else
					self->dec_finished();
				workers.at(id)->working = false;
				run_task(id);
			}
			catch (...) {}
		});
	});
}
