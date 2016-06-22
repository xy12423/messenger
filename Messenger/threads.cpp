#include "stdafx.h"
#include "crypto.h"
#include "session.h"
#include "threads.h"

extern std::unordered_map<user_id_type, user_ext_type> user_ext;

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

void fileSendThread::start(user_id_type uID, const fs::path& path)
{
	iosrv.post([this, uID, path]() {
		bool write_not_in_progress = tasks.empty();
		tasks.push_back(fileSendTask(uID, path));
		fileSendTask &newTask = tasks.back();

		if (newTask.fin.is_open())
		{
			data_size_type blockCountAll = static_cast<data_size_type>(fs::file_size(path));
			if (blockCountAll == 0)
			{
				tasks.pop_back();
				return;
			}
			if (blockCountAll % fileBlockLen == 0)
				blockCountAll /= fileBlockLen;
			else
				blockCountAll = blockCountAll / fileBlockLen + 1;
			newTask.blockCountAll = blockCountAll;

			std::wstring fileName = path.leaf().wstring();
			data_size_type blockCountAll_LE = wxUINT32_SWAP_ON_BE(blockCountAll);
			std::string head(1, PAC_TYPE_FILE_H);
			head.append(reinterpret_cast<const char*>(&blockCountAll_LE), sizeof(data_size_type));
			std::string name(wxConvUTF8.cWC2MB(fileName.c_str()));
			insLen(name);
			head.append(name);

			wxCharBuffer msgBuf = wxConvLocal.cWC2MB(
				(wxT("Sending file ") + fileName + wxT(" To ") + user_ext[uID].addr).c_str()
				);
			srv.send_data(uID, std::move(head), msgr_proto::session::priority_file, std::string(msgBuf.data(), msgBuf.length()));
			
			if (write_not_in_progress)
				write();
		}
		else
		{
			tasks.pop_back();
			return;
		}
	});
}

void fileSendThread::stop(user_id_type uID)
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
	sendBuf.push_back(PAC_TYPE_FILE_B);
	data_size_type len = boost::endian::native_to_little(static_cast<data_size_type>(sizeRead));
	sendBuf.append(reinterpret_cast<const char*>(&len), sizeof(data_size_type));
	sendBuf.append(block.get(), sizeRead);
	
	wxCharBuffer msgBuf = wxConvLocal.cWC2MB(
		(task.fileName + wxT(":Sended block ") + std::to_wstring(task.blockCount) + wxT("/") + std::to_wstring(task.blockCountAll) + wxT(" To ") + user_ext[task.uID].addr).c_str()
		);
	std::string msg(msgBuf.data(), msgBuf.length());
	srv.send_data(task.uID, std::move(sendBuf), msgr_proto::session::priority_file, [msg, this]() {
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
