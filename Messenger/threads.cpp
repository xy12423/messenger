#include "stdafx.h"
#include "global.h"
#include "threads.h"
#include "crypto.h"
#include "main.h"

extern userList users;
extern mainFrame *form;
volatile int onDelID = -1;
#define checkID if (onDelID == task.uID) continue
#define checkIDT if (onDelID == task.uID) throw(0)
#define checkIDP if (onDelID == uID) continue
#define checkIDPT if (onDelID == uID) throw(0)

pingThread::ExitCode pingThread::Entry()
{
	userList::iterator itr, itrEnd;
	while (!TestDestroy())
	{
		itr = users.begin();
		itrEnd = users.end();
		for (; itr != itrEnd && (!TestDestroy()); itr++)
		{
			std::mutex *lock = NULL;
			try
			{
				int uID = itr->second.uID;
				checkIDP;
				user &usr = itr->second;
				checkIDP;
				lock = usr.lock;
				lock->lock();
				checkIDPT;
				usr.con->Write("\0", 1);
				lock->unlock();
			}
			catch (std::exception ex)
			{
				wxThreadEvent *newEvent = new wxThreadEvent;
				newEvent->SetString(wxString(ex.what()) + "\n");
				wxQueueEvent(form, newEvent);
				if (lock != NULL)
					lock->unlock();
			}
			catch (...)
			{
				if (lock != NULL)
					lock->unlock();
			}
		}
		wxSleep(1);
	}
	return NULL;
}

msgThread::ExitCode msgThread::Entry()
{
	while (!TestDestroy())
	{
		std::mutex *lock = NULL;
		try
		{
			msgTask task;
			wxMessageQueueError err = taskQue.ReceiveTimeout(100, task);
			if (err != wxMSGQUEUE_NO_ERROR)
				continue;
			checkID;
			std::unordered_map<int, user>::iterator itr = users.find(task.uID);
			if (itr == users.end())
				continue;
			checkID;
			user &usr = itr->second;
			checkID;
			lock = usr.lock;
			lock->lock();
			checkIDT;
			std::string sendMsg;
			encrypt(task.msg, sendMsg, usr.e1);
			insLen(sendMsg);
			sendMsg.insert(0, "\x01");
			usr.con->Write(sendMsg.c_str(), sendMsg.size());
			lock->unlock();
		}
		catch (std::exception ex)
		{
			wxThreadEvent *newEvent = new wxThreadEvent;
			newEvent->SetString(wxString(ex.what()) + "\n");
			wxQueueEvent(form, newEvent);
			if (lock != NULL)
				lock->unlock();
		}
		catch (...)
		{
			if (lock != NULL)
				lock->unlock();
		}
	}
	return NULL;
}

const int fileBlockLen = 0x40000;

fileThread::ExitCode fileThread::Entry()
{
	while (!TestDestroy())
	{
		std::mutex *lock = NULL;
		char *block = NULL;
		try
		{
			fileTask task;
			wxMessageQueueError err = taskQue.ReceiveTimeout(100, task);
			if (err != wxMSGQUEUE_NO_ERROR)
				continue;
			checkID;
			std::unordered_map<int, user>::iterator itr = users.find(task.uID);
			if (itr == users.end())
				continue;
			checkID;

			user &usr = itr->second;
			checkID;
			lock = usr.lock;
			lock->lock();
			checkIDT;

			std::ifstream fin(task.path.string(), std::ios::in | std::ios::binary);
			if (fin.is_open())
			{
				unsigned int len = static_cast<unsigned int>(fs::file_size(task.path));
				if (len % fileBlockLen == 0)
					len /= fileBlockLen;
				else
					len = len / fileBlockLen + 1;
				std::wstring fileName = task.path.leaf().wstring();
				{
					unsigned int lenSend = wxUINT32_SWAP_ON_BE(len);
					std::string head(reinterpret_cast<const char*>(&len), sizeof(unsigned int) / sizeof(char));
					head.insert(0, "\x02");
					wxCharBuffer nameBuf = wxConvUTF8.cWC2MB(fileName.c_str());
					std::string name(nameBuf, nameBuf.length());
					insLen(name);
					head.append(name);

					checkIDT;
					usr.con->Write(head.c_str(), head.size());
					wxThreadEvent *newEvent = new wxThreadEvent;
					newEvent->SetString("Sending file " + fileName + " To " + usr.addr.IPAddress() + '\n');
					wxQueueEvent(form, newEvent);
				}

				block = new char[fileBlockLen];
				std::string buf;
				int blockCount = 1;
				while (!fin.eof())
				{
					fin.read(block, fileBlockLen);
					std::streamsize count = fin.gcount();
					encrypt(std::string(block, count), buf, itr->second.e1);
					insLen(buf);
					buf.insert(0, "\x03");
					checkIDT;
					usr.con->Write(buf.c_str(), buf.size());
					wxThreadEvent *newEvent = new wxThreadEvent;
					newEvent->SetString(fileName + ":Sended block " + num2str(blockCount) + " To " + usr.addr.IPAddress() + '\n');
					wxQueueEvent(form, newEvent);
					blockCount++;
				}

				wxThreadEvent *newEvent = new wxThreadEvent;
				newEvent->SetString("Finished Sending\n");
				wxQueueEvent(form, newEvent);
				fin.close();
			}

			lock->unlock();
		}
		catch (std::exception ex)
		{
			wxThreadEvent *newEvent = new wxThreadEvent;
			newEvent->SetString(wxString(ex.what()) + "\n");
			wxQueueEvent(form, newEvent);
			if (lock != NULL)
				lock->unlock();
			if (block != NULL)
				delete[] block;
		}
		catch (int)
		{
			wxThreadEvent *newEvent = new wxThreadEvent;
			newEvent->SetString("Finished Sending (disconnected)\n");
			wxQueueEvent(form, newEvent);
			if (lock != NULL)
				lock->unlock();
			if (block != NULL)
				delete[] block;
		}
		catch (...)
		{
			if (lock != NULL)
				lock->unlock();
			if (block != NULL)
				delete[] block;
		}
	}
	return NULL;
}
