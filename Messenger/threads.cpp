#include "stdafx.h"
#include "global.h"
#include "session.h"
#include "threads.h"

extern server *srv;
extern std::unordered_map<int, user_ext_data> user_ext;

const int checkInterval = 10;

iosrvThread::ExitCode iosrvThread::Entry()
{
	iosrv_work = std::make_shared<net::io_service::work>(iosrv);
	while (!TestDestroy())
	{
		try
		{
			iosrv.run();
		}
		catch(...){}
	}
	return NULL;
}

const int fileBlockLen = 0x100000;

fileSendThread::ExitCode fileSendThread::Entry()
{
	while (!TestDestroy())
	{
		char *block = nullptr;
		try
		{
			fileSendTask task;
			wxMessageQueueError err = taskQue.ReceiveTimeout(checkInterval, task);
			if (err != wxMSGQUEUE_NO_ERROR)
				continue;

			std::ifstream fin(task.path.string(), std::ios::in | std::ios::binary);
			if (fin.is_open())
			{
				data_length_type blockCountAll = static_cast<data_length_type>(fs::file_size(task.path));
				if (blockCountAll % fileBlockLen == 0)
					blockCountAll /= fileBlockLen;
				else
					blockCountAll = blockCountAll / fileBlockLen + 1;
				std::wstring fileName = task.path.leaf().wstring();
				{
					data_length_type lenSend = wxUINT32_SWAP_ON_BE(blockCountAll);
					std::string head(reinterpret_cast<const char*>(&blockCountAll), sizeof(data_length_type));
					head.insert(0, "\xFE");
					wxCharBuffer nameBuf = wxConvUTF8.cWC2MB(fileName.c_str());
					std::string name(nameBuf, nameBuf.length());
					insLen(name);
					head.append(name);

					if (TestDestroy())
						break;
					srv->send_data(task.uID, head, session::priority_file, wxT("Sending file ") + fileName + wxT(" To ") + user_ext[task.uID].addr);
				}

				block = new char[fileBlockLen];
				std::string buf;
				int blockCount = 1;
				while (!(fin.eof() || TestDestroy()))
				{
					fin.read(block, fileBlockLen);
					std::streamsize count = fin.gcount();
					buf.assign(block, count);
					insLen(buf);
					buf.insert(0, "\xFD");
					if (TestDestroy())
						break;
					srv->send_data(task.uID, buf, session::priority_file, fileName + wxT(":Sended block ") + std::to_wstring(blockCount) + wxT("/") + std::to_wstring(blockCountAll) + wxT(" To ") + user_ext[task.uID].addr);
					blockCount++;
				}
				delete[] block;
				block = nullptr;

				fin.close();
			}
		}
		catch (std::exception ex)
		{
			std::cerr << ex.what() << std::endl;
			if (block != nullptr)
				delete[] block;
		}
		catch (int)
		{
			std::cerr << "Finished Sending (disconnected)\n" << std::endl;
			if (block != nullptr)
				delete[] block;
		}
		catch (...)
		{
			if (block != nullptr)
				delete[] block;
		}
	}
	return NULL;
}
