#include "stdafx.h"
#include "crypto.h"
#include "session.h"
#include "threads.h"

extern std::unordered_map<user_id_type, user_ext_type> user_ext;

iosrvThread::ExitCode iosrvThread::Entry()
{
	iosrv_work = std::make_shared<asio::io_service::work>(iosrv);
	while (iosrv_work)
	{
		try
		{
			iosrv.run();
		}
		catch (std::exception &ex) { std::cerr << ex.what() << std::endl; }
		catch (...) {}
	}
	while (!TestDestroy());
	return NULL;
}

void FileSendThread::start(user_id_type uID, const fs::path& path)
{
	iosrv.post([this, uID, path]() {
		TaskListTp &tasks = task_list[uID];
		bool write_not_in_progress = tasks.empty();
		tasks.push_back(FileSendTask(uID, path));
		FileSendTask &newTask = tasks.back();

		if (newTask.fin.is_open())
		{
			data_size_type blockCountAll = static_cast<data_size_type>(fs::file_size(path));
			if (blockCountAll % FileBlockLen == 0)
				blockCountAll /= FileBlockLen;
			else
				blockCountAll = blockCountAll / FileBlockLen + 1;
			if (blockCountAll < 1)
			{
				tasks.pop_back();
				if (tasks.empty())
					task_list.erase(uID);
				return;
			}
			newTask.blockCountAll = blockCountAll;

			if (write_not_in_progress)
				write(uID);
		}
		else
		{
			tasks.pop_back();
			if (tasks.empty())
				task_list.erase(uID);
			return;
		}
	});
}

void FileSendThread::send_header(FileSendTask &task)
{
	const std::wstring &fileName = fs::path(task.file_name).filename().wstring();
	std::string name(wxConvUTF8.cWC2MB(fileName.c_str()));
	data_size_type block_count_all = task.blockCountAll;
	size_t name_size = name.size();

	std::string head(1, PAC_TYPE_FILE_H);
	head.reserve(1 + sizeof(data_size_type) + sizeof(data_size_type) + name_size);
	for (int i = 0; i < sizeof(data_size_type); i++)
	{
		head.push_back(static_cast<uint8_t>(block_count_all));
		block_count_all >>= 8;
	}
	for (int i = 0; i < sizeof(data_size_type); i++)
	{
		head.push_back(static_cast<uint8_t>(name_size));
		name_size >>= 8;
	}
	head.append(name);

	wxCharBuffer msgBuf = wxConvLocal.cWC2MB(
		(wxT("Sending file ") + fileName + wxT(" To ") + user_ext[task.uID].addr).c_str()
	);
	srv.send_data(task.uID, std::move(head), msgr_proto::session::priority_file, std::string(msgBuf.data(), msgBuf.length()));
}

void FileSendThread::stop(user_id_type uID)
{
	if (stopping)
		return;
	iosrv.post([this, uID]() {
		task_list.erase(uID);
	});
}

void FileSendThread::write(user_id_type uID)
{
	std::string sendBuf;

	TaskListTp &tasks = task_list.at(uID);
	FileSendTask &task = tasks.front();
	if (task.blockCount == 1)
		send_header(task);

	task.fin.read(block.get(), FileBlockLen);
	std::streamsize sizeRead = task.fin.gcount();
	sendBuf.push_back(PAC_TYPE_FILE_B);
	data_size_type len = boost::endian::native_to_little(static_cast<data_size_type>(sizeRead));
	sendBuf.append(reinterpret_cast<const char*>(&len), sizeof(data_size_type));
	sendBuf.append(block.get(), sizeRead);

	wxCharBuffer msgBuf = wxConvLocal.cWC2MB(
		(task.file_name + wxT(":Sended block ") + std::to_wstring(task.blockCount) + wxT("/") + std::to_wstring(task.blockCountAll) + wxT(" To ") + user_ext[task.uID].addr).c_str()
		);
	std::string msg(msgBuf.data(), msgBuf.length());
	srv.send_data(task.uID, std::move(sendBuf), msgr_proto::session::priority_file, [this, msg, uID]() {
		std::cout << msg << std::endl;
		if (stopping)
			return;
		iosrv.post([this, uID]() {
			if (task_list.count(uID) > 0)
				write(uID);
		});
	});
	task.blockCount++;

	if (task.blockCount > task.blockCountAll || task.fin.eof())
	{
		tasks.pop_front();
		if (tasks.empty())
			task_list.erase(uID);
	}
}

FileSendThread::ExitCode FileSendThread::Entry()
{
	iosrv_work = std::make_shared<asio::io_service::work>(iosrv);
	while (iosrv_work)
	{
		try
		{
			iosrv.run();
		}
		catch (std::exception &ex) { std::cerr << ex.what() << std::endl; }
		catch (...) {}
	}
	while (!TestDestroy());
	return NULL;
}
