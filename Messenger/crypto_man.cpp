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
	iosrv.post([this, self = shared_from_this(), new_task]() {
		srv.new_task(id, ENC, std::move(*new_task));
	});
}

void session::dec(std::string& data, crypto_callback&& _callback)
{
	std::shared_ptr<task> new_task = std::make_shared<task>(data, std::move(_callback));
	iosrv.post([this, self = shared_from_this(), new_task]() {
		srv.new_task(id, DEC, std::move(*new_task));
	});
}

void session::stop()
{
	iosrv.post([this]() {
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
	std::unordered_map<id_type, session_data_ptr>::iterator itr = sessions_data.find(id);
	if (itr == sessions_data.end())
		return;

	itr->second->exiting = true;
	task_list_tp::iterator task_itr = tasks.begin(), task_itr_end = tasks.end();
	while (task_itr != task_itr_end)
	{
		if (task_itr->first == id)
			task_itr = tasks.erase(task_itr);
		else
			task_itr++;
	}

	if (itr->second->available(ENC))
		itr->second->enc_finished();
	if (itr->second->available(DEC))
		itr->second->dec_finished();

	sessions_data.erase(itr);
	sessions.erase(id);
}

void server::new_task(id_type id, task_type type, task&& task)
{
	session_data_ptr &self = sessions_data.at(id);

	if (self->exiting)
		return;
	if (type == ENC)
		self->enc_task_que.push_back(std::move(task));
	else
		self->dec_task_que.push_back(std::move(task));

	tasks.emplace_back(id, type);
	if (!self->available(type))
		return;

	for (const std::unordered_map<id_type, std::unique_ptr<worker>>::value_type& pair : workers)
	{
		if (!pair.second->working)
		{
			work(pair.first);
			break;
		}
	}
}

void server::work(id_type worker_id)
{
	if (stopping)
		return;
	worker &w = *workers.at(worker_id);

	task_list_tp::iterator task_itr = tasks.begin(), task_itr_end = tasks.end();
	for (; task_itr != task_itr_end; task_itr++)
		if (sessions_data.at(task_itr->first)->available(task_itr->second))
			break;
	if (task_itr == task_itr_end)
		return;
	session_ptr &ses_self = sessions.at(task_itr->first);
	session_data_ptr &self = sessions_data.at(task_itr->first);
	task_type type = task_itr->second;
	tasks.erase(task_itr);
	self->set_busy(type);
	w.working = true;

	w.iosrv.post([this, ses_self, self, worker_id, type]() {
		try
		{
			if (type == ENC)
				ses_self->do_enc(self->enc_task_que.front());
			else
				ses_self->do_dec(self->dec_task_que.front());
		}
		catch (...) {}

		iosrv.post([this, self, worker_id, type]() {
			try
			{
				if (type == ENC)
					self->enc_finished();
				else
					self->dec_finished();
				workers.at(worker_id)->working = false;
				work(worker_id);
			}
			catch (...) {}
		});
	});
}
