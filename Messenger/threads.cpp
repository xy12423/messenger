#include "stdafx.h"
#include "crypto.h"
#include "session.h"
#include "threads.h"

extern server *srv;
extern std::unordered_map<int, user_ext_data> user_ext;

const int checkInterval = 10;

iosrvThread::ExitCode iosrvThread::Entry()
{
	iosrv_work = std::make_shared<asio::io_service::work>(iosrv);
	while (!TestDestroy())
	{
		try
		{
			iosrv.run();
		}
		catch (std::exception &ex) { std::cerr << ex.what() << std::endl; }
		catch (...) {}
	}
	return NULL;
}

void fileSendThread::start(int uID, const fs::path &path)
{
	iosrv.post([this, uID, path]() {
		bool write_not_in_progress = tasks.empty();
		tasks.push_back(fileSendTask(uID, path));
		fileSendTask &newTask = tasks.back();

		if (newTask.fin.is_open())
		{
			data_length_type blockCountAll = static_cast<data_length_type>(fs::file_size(path));
			if (blockCountAll == 0)
				throw(0);
			if (blockCountAll % fileBlockLen == 0)
				blockCountAll /= fileBlockLen;
			else
				blockCountAll = blockCountAll / fileBlockLen + 1;
			newTask.blockCountAll = blockCountAll;

			std::wstring fileName = path.leaf().wstring();
			data_length_type blockCountAll_LE = wxUINT32_SWAP_ON_BE(blockCountAll);
			std::string head(1, pac_type_file_h);
			head.append(reinterpret_cast<const char*>(&blockCountAll_LE), sizeof(data_length_type));
			wxCharBuffer nameBuf = wxConvUTF8.cWC2MB(fileName.c_str());
			std::string name(nameBuf, nameBuf.length());
			insLen(name);
			head.append(name);

			wxCharBuffer msgBuf = wxConvLocal.cWC2MB(
				(wxT("Sending file ") + fileName + wxT(" To ") + user_ext[uID].addr).c_str()
				);
			srv->send_data(uID, head, session::priority_file, std::string(msgBuf.data(), msgBuf.length()));
			
			if (write_not_in_progress)
				write();
		}
	});
}

void fileSendThread::stop(int uID)
{
	iosrv.post([this, uID]() {
		for (std::list<fileSendTask>::iterator itr = tasks.begin(), itrEnd = tasks.end(); itr != itrEnd;)
		{
			if (itr->uID == uID)
				itr = tasks.erase(itr);
			else
				itr++;
		}
	});
}

void fileSendThread::write()
{
	std::string sendBuf;

	fileSendTask &task = tasks.front();
	task.fin.read(block.get(), fileBlockLen);
	std::streamsize sizeRead = task.fin.gcount();
	sendBuf.assign(block.get(), sizeRead);
	insLen(sendBuf);
	sendBuf.insert(0, 1, pac_type_file_b);
	wxCharBuffer msgBuf = wxConvLocal.cWC2MB(
		(task.fileName + wxT(":Sended block ") + std::to_wstring(task.blockCount) + wxT("/") + std::to_wstring(task.blockCountAll) + wxT(" To ") + user_ext[task.uID].addr).c_str()
		);
	std::string msg(msgBuf.data(), msgBuf.length());
	srv->send_data(task.uID, sendBuf, session::priority_file, [msg, this]() {
		std::cout << msg << std::endl;
		iosrv.post([this]() {
			if (!tasks.empty())
				write();
		});
	});
	task.blockCount++;

	if (task.fin.eof())
		tasks.pop_front();
}

fileSendThread::ExitCode fileSendThread::Entry()
{
	iosrv_work = std::make_shared<asio::io_service::work>(iosrv);
	while (!TestDestroy())
	{
		try
		{
			iosrv.run();
		}
		catch (std::exception &ex) { std::cerr << ex.what() << std::endl; }
		catch (...) {}
	}
	return NULL;
}
