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
				if (!lock->try_lock())
					continue;
				checkIDPT;
				usr.con->Write("\0", 1);
				lock->unlock();
			}
			catch (std::exception ex)
			{
				wxThreadEvent *newEvent = new wxThreadEvent;
				newEvent->SetInt(-1);
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
			if (!lock->try_lock())
			{
				taskQue.Post(task);
				continue;
			}
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
			newEvent->SetInt(-1);
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

const int fileBlockLen = 0x200000;

fileSendThread::ExitCode fileSendThread::Entry()
{
	while (!TestDestroy())
	{
		std::mutex *lock = NULL;
		char *block = NULL;
		try
		{
			fileSendTask task;
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
			if (!lock->try_lock())
			{
				taskQue.Post(task);
				continue;
			}
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
					newEvent->SetInt(-1);
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
					newEvent->SetInt(-1);
					newEvent->SetString(fileName + ":Sended block " + num2str(blockCount) + " To " + usr.addr.IPAddress() + '\n');
					wxQueueEvent(form, newEvent);
					blockCount++;
				}

				wxThreadEvent *newEvent = new wxThreadEvent;
				newEvent->SetInt(-1);
				newEvent->SetString("Finished Sending\n");
				wxQueueEvent(form, newEvent);
				fin.close();
			}

			lock->unlock();
		}
		catch (std::exception ex)
		{
			wxThreadEvent *newEvent = new wxThreadEvent;
			newEvent->SetInt(-1);
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
			newEvent->SetInt(-1);
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

#define checkErr if (con->Error()) throw(con->LastError())

recvThread::ExitCode recvThread::Entry()
{
	while (!TestDestroy())
	{
		std::mutex *lock = NULL;
		try
		{
			int uID;
			wxMessageQueueError err = taskQue.ReceiveTimeout(100, uID);
			if (err != wxMSGQUEUE_NO_ERROR)
				continue;
			checkIDP;
			std::unordered_map<int, user>::iterator itr = users.find(uID);
			if (itr == users.end())
				continue;
			checkIDP;
			user &usr = itr->second;
			checkIDP;
			lock = usr.lock;
			if (!lock->try_lock())
			{
				taskQue.Post(uID);
				continue;
			}
			checkIDPT;
			
			wxSocketBase *con = usr.con;
			byte type;
			con->Read(&type, sizeof(byte));
			switch (type)
			{
				case 1:
				{
					long timeout = con->GetTimeout();
					con->SetTimeout(5);

					unsigned int sizeRecvLE;
					con->Read(&sizeRecvLE, sizeof(unsigned int) / sizeof(char));
					checkErr;
					unsigned int sizeRecv = wxUINT32_SWAP_ON_BE(static_cast<unsigned int>(sizeRecvLE));

					char *buf = new char[sizeRecv];
					con->Read(buf, sizeRecv);
					checkErr;
					std::string str(buf, sizeRecv);
					delete[] buf;
					std::string ret;
					decrypt(str, ret);

					wxThreadEvent *newEvent = new wxThreadEvent;
					newEvent->SetInt(uID);
					newEvent->SetString(usr.addr.IPAddress() + ':' + wxConvUTF8.cMB2WC(ret.c_str()) + '\n');
					wxQueueEvent(form, newEvent);

					con->SetTimeout(timeout);
					break;
				}
				case 2:
				{
					long timeout = con->GetTimeout();
					con->SetTimeout(5);

					unsigned int recvLE;
					con->Read(&recvLE, sizeof(unsigned int) / sizeof(char));
					checkErr;
					unsigned int blockCount = wxUINT32_SWAP_ON_BE(static_cast<unsigned int>(recvLE));

					con->Read(&recvLE, sizeof(unsigned int) / sizeof(char));
					checkErr;
					unsigned int fNameLen = wxUINT32_SWAP_ON_BE(static_cast<unsigned int>(recvLE));

					char *buf = new char[fNameLen];
					con->Read(buf, fNameLen);
					checkErr;
					std::wstring fName;
					{
						size_t tmp;
						wxWCharBuffer wbuf = wxConvUTF8.cMB2WC(buf, fNameLen, &tmp);
						fName = std::wstring(wbuf, tmp);
					}
					delete[] buf;

					if (fs::exists(fName))
					{
						int i;
						for (i = 0; i < INT_MAX; i++)
						{
							if (!fs::exists(fs::path(fName + "_" + num2str(i))))
								break;
						}
						if (i == INT_MAX)
							throw(std::runtime_error("Failed to open file"));
						fName = fName + "_" + num2str(i);
					}
					usr.recvFile = wxConvLocal.cWC2MB(fName.c_str());
					usr.blockLast = blockCount;
					wxThreadEvent *newEvent = new wxThreadEvent;
					newEvent->SetInt(-1);
					newEvent->SetString("Receiving file " + fName + " from " + usr.addr.IPAddress() + "\n");
					wxQueueEvent(form, newEvent);

					con->SetTimeout(timeout);
					break;
				}
				case 3:
				{
					long timeout = con->GetTimeout();
					con->SetTimeout(60);

					unsigned int recvLE;
					con->Read(&recvLE, sizeof(unsigned int) / sizeof(char));
					checkErr;
					unsigned int recvLen = wxUINT32_SWAP_ON_BE(static_cast<unsigned int>(recvLE));

					char *buf = new char[recvLen];
					con->Read(buf, recvLen);
					checkErr;
					std::string data;
					decrypt(std::string(buf, recvLen), data);
					delete[] buf;

					if (usr.blockLast > 0)
					{
						std::ofstream fout(usr.recvFile, std::ios::out | std::ios::binary | std::ios::app);
						fout.write(data.c_str(), data.size());
						fout.close();
						usr.blockLast--;
						wxThreadEvent *newEvent = new wxThreadEvent;
						newEvent->SetInt(-1);
						newEvent->SetString(usr.recvFile + ":" + num2str(usr.blockLast) + " block(s) last\n");
						wxQueueEvent(form, newEvent);
						if (usr.blockLast == 0)
							usr.recvFile.clear();
					}

					con->SetTimeout(timeout);
					break;
				}
			}

			lock->unlock();
		}
		catch (std::exception ex)
		{
			wxThreadEvent *newEvent = new wxThreadEvent;
			newEvent->SetInt(-1);
			newEvent->SetString(wxString(ex.what()) + "\n");
			wxQueueEvent(form, newEvent);
			if (lock != NULL)
				lock->unlock();
		}
		catch (wxSocketError err)
		{
			std::string errStr;
			switch (err)
			{
				case wxSOCKET_INVOP:
					errStr = "Socket:Invalid operation";
					break;
				case wxSOCKET_IOERR:
					errStr = "Socket:IO error";
					break;
				case wxSOCKET_INVSOCK:
					errStr = "Socket:Invalid socket";
					break;
				case wxSOCKET_NOHOST:
					errStr = "Socket:No corresponding host";
					break;
				case wxSOCKET_TIMEDOUT:
					errStr = "Socket:Operation timed out";
					break;
				case wxSOCKET_INVADDR:
					errStr = "Socket:Invalid address";
					break;
				case wxSOCKET_INVPORT:
					errStr = "Socket:Invalid port";
					break;
				case wxSOCKET_MEMERR:
					errStr = "Socket:Memory exhausted";
					break;
				default:
					errStr = "Socket:Error";
			}
			wxThreadEvent *newEvent = new wxThreadEvent;
			newEvent->SetInt(-1);
			newEvent->SetString(errStr + "\n");
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
