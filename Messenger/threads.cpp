#include "stdafx.h"
#include "global.h"
#include "threads.h"
#include "crypto.h"
#include "main.h"

extern userList users;
extern mainFrame *form;
extern sendThread *threadSend;
volatile int onDelID = -1;
#define checkID if (onDelID == task.uID) continue
#define checkIDP if (onDelID == uID) continue
#define checkIDT if (onDelID == task.uID) throw(0)

const int checkInterval = 10;

pingThread::ExitCode pingThread::Entry()
{
	userList::iterator itr, itrEnd;
	while (!TestDestroy())
	{
		itr = users.begin();
		itrEnd = users.end();
		for (; itr != itrEnd && (!TestDestroy()); itr++)
		{
			try
			{
				int uID = itr->second.uID;
				checkIDP;
				user &usr = itr->second;
				checkIDP;
				threadSend->taskQue.Post(sendTask(uID, std::string("\0"), wxString()));
			}
			catch (std::exception ex)
			{
				wxThreadEvent *newEvent = new wxThreadEvent;
				newEvent->SetInt(-1);
				newEvent->SetString(wxString(ex.what()) + "\n");
				wxQueueEvent(form, newEvent);
			}
			catch (...)
			{
			}
		}
		wxSleep(1);
	}
	return NULL;
}


sendThread::ExitCode sendThread::Entry()
{
	while (!TestDestroy())
	{
		try
		{
			sendTask task;
			wxMessageQueueError err = taskQue.ReceiveTimeout(checkInterval, task);
			if (err != wxMSGQUEUE_NO_ERROR)
				continue;
			checkID;
			std::unordered_map<int, user>::iterator itr = users.find(task.uID);
			if (itr == users.end())
				continue;
			checkID;
			user &usr = itr->second;
			checkID;
			if (!task.data.empty())
			{
				std::string sendData;
				encrypt(task.data, sendData, usr.e1);
				insLen(sendData);
				usr.con->WaitForWrite();
				usr.con->Write(sendData.c_str(), sendData.size());
			}
			if (!task.msg.empty())
			{
				wxThreadEvent *newEvent = new wxThreadEvent;
				newEvent->SetInt(-1);
				newEvent->SetString(task.msg);
				wxQueueEvent(form, newEvent);
			}
		}
		catch (std::exception ex)
		{
			wxThreadEvent *newEvent = new wxThreadEvent;
			newEvent->SetInt(-1);
			newEvent->SetString(wxString(ex.what()) + "\n");
			wxQueueEvent(form, newEvent);
		}
		catch (...)
		{
		}
	}
	return NULL;
}

msgSendThread::ExitCode msgSendThread::Entry()
{
	while (!TestDestroy())
	{
		try
		{
			msgSendTask task;
			wxMessageQueueError err = taskQue.ReceiveTimeout(checkInterval, task);
			if (err != wxMSGQUEUE_NO_ERROR)
				continue;
			checkID;
			std::unordered_map<int, user>::iterator itr = users.find(task.uID);
			if (itr == users.end())
				continue;
			checkID;
			std::string sendMsg(task.msg);
			checkID;
			insLen(sendMsg);
			sendMsg.insert(0, "\x01");
			threadSend->taskQue.Post(sendTask(task.uID, sendMsg, wxString()));
		}
		catch (std::exception ex)
		{
			wxThreadEvent *newEvent = new wxThreadEvent;
			newEvent->SetInt(-1);
			newEvent->SetString(wxString(ex.what()) + "\n");
			wxQueueEvent(form, newEvent);
		}
		catch (...)
		{
		}
	}
	return NULL;
}

const int fileBlockLen = 0x100000;

fileSendThread::ExitCode fileSendThread::Entry()
{
	while (!TestDestroy())
	{
		char *block = NULL;
		try
		{
			fileSendTask task;
			wxMessageQueueError err = taskQue.ReceiveTimeout(checkInterval, task);
			if (err != wxMSGQUEUE_NO_ERROR)
				continue;
			checkID;
			std::unordered_map<int, user>::iterator itr = users.find(task.uID);
			if (itr == users.end())
				continue;
			checkID;

			user &usr = itr->second;
			checkID;

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
					threadSend->taskQue.Post(sendTask(task.uID, head, "Sending file " + fileName + " To " + usr.addr.IPAddress() + '\n'));
				}

				block = new char[fileBlockLen];
				std::string buf;
				int blockCount = 1;
				while (!fin.eof())
				{
					fin.read(block, fileBlockLen);
					std::streamsize count = fin.gcount();
					checkIDT;
					buf = std::string(block, count);
					insLen(buf);
					buf.insert(0, "\x03");
					checkIDT;
					threadSend->taskQue.Post(sendTask(task.uID, buf, fileName + ":Sended block " + num2str(blockCount) + " To " + usr.addr.IPAddress() + '\n'));
					blockCount++;
				}

				threadSend->taskQue.Post(sendTask(task.uID, std::string(), wxString("Finished Sending\n")));
				fin.close();
			}
		}
		catch (std::exception ex)
		{
			wxThreadEvent *newEvent = new wxThreadEvent;
			newEvent->SetInt(-1);
			newEvent->SetString(wxString(ex.what()) + "\n");
			wxQueueEvent(form, newEvent);
			if (block != NULL)
				delete[] block;
		}
		catch (int)
		{
			wxThreadEvent *newEvent = new wxThreadEvent;
			newEvent->SetInt(-1);
			newEvent->SetString("Finished Sending (disconnected)\n");
			wxQueueEvent(form, newEvent);
			if (block != NULL)
				delete[] block;
		}
		catch (...)
		{
			if (block != NULL)
				delete[] block;
		}
	}
	return NULL;
}

#define checkErr(x) if ((inItr + (x)) >= inItrEnd) throw(wxSOCKET_TIMEDOUT)

recvThread::ExitCode recvThread::Entry()
{
	while (!TestDestroy())
	{
		char *buf = NULL;
		try
		{
			int uID;
			wxMessageQueueError err = taskQue.ReceiveTimeout(checkInterval, uID);
			if (err != wxMSGQUEUE_NO_ERROR)
				continue;
			checkIDP;
			std::unordered_map<int, user>::iterator itr = users.find(uID);
			if (itr == users.end())
				continue;
			checkIDP;
			user &usr = itr->second;
			checkIDP;

			wxSocketBase *con = usr.con;
			unsigned int sizePacketLE;
			con->WaitForRead();
			con->Read(&sizePacketLE, sizeof(unsigned int) / sizeof(char));
			unsigned int sizePacket = wxUINT32_SWAP_ON_BE(static_cast<unsigned int>(sizePacketLE));

			con->SetTimeout(30);
			buf = new char[sizePacket];
			con->WaitForRead();
			con->Read(buf, sizePacket);

			std::string in;
			const char *inItr = in.data(), *inItrEnd = in.data() + in.size();
			decrypt(std::string(buf, sizePacket), in);
			
			delete[] buf;
			buf = NULL;

			byte type;
			*reinterpret_cast<char*>(&type) = *inItr;
			inItr++;
			in.erase(0, 1);
			switch (type)
			{
				case 1:
				{
					unsigned int sizeRecvLE;
					checkErr(sizeof(unsigned int) / sizeof(char));
					memcpy(reinterpret_cast<char*>(&sizeRecvLE), inItr, sizeof(unsigned int) / sizeof(char));
					inItr += sizeof(unsigned int) / sizeof(char);
					unsigned int sizeRecv = wxUINT32_SWAP_ON_BE(static_cast<unsigned int>(sizeRecvLE));

					buf = new char[sizeRecv];
					checkErr(sizeRecv);
					memcpy(buf, inItr, sizeRecv);
					inItr += sizeRecv;
					std::string str(buf, sizeRecv);
					delete[] buf;
					buf = NULL;

					wxThreadEvent *newEvent = new wxThreadEvent;
					newEvent->SetInt(uID);
					newEvent->SetString(usr.addr.IPAddress() + ':' + wxConvUTF8.cMB2WC(str.c_str()) + '\n');
					wxQueueEvent(form, newEvent);

					break;
				}
				case 2:
				{
					unsigned int recvLE;
					checkErr(sizeof(unsigned int) / sizeof(char));
					memcpy(reinterpret_cast<char*>(&recvLE), inItr, sizeof(unsigned int) / sizeof(char));
					inItr += sizeof(unsigned int) / sizeof(char);
					unsigned int blockCount = wxUINT32_SWAP_ON_BE(static_cast<unsigned int>(recvLE));

					checkErr(sizeof(unsigned int) / sizeof(char));
					memcpy(reinterpret_cast<char*>(&recvLE), inItr, sizeof(unsigned int) / sizeof(char));
					inItr += sizeof(unsigned int) / sizeof(char);
					unsigned int fNameLen = wxUINT32_SWAP_ON_BE(static_cast<unsigned int>(recvLE));

					buf = new char[fNameLen];
					checkErr(fNameLen);
					memcpy(buf, inItr, fNameLen);
					inItr += fNameLen;
					std::wstring fName;
					{
						size_t tmp;
						wxWCharBuffer wbuf = wxConvUTF8.cMB2WC(buf, fNameLen, &tmp);
						fName = std::wstring(wbuf, tmp);
					}
					delete[] buf;
					buf = NULL;

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

					break;
				}
				case 3:
				{
					unsigned int recvLE;
					checkErr(sizeof(unsigned int) / sizeof(char));
					memcpy(reinterpret_cast<char*>(&recvLE), inItr, sizeof(unsigned int) / sizeof(char));
					inItr += sizeof(unsigned int) / sizeof(char);
					unsigned int recvLen = wxUINT32_SWAP_ON_BE(static_cast<unsigned int>(recvLE));

					buf = new char[recvLen];
					checkErr(recvLen);
					memcpy(buf, inItr, recvLen);
					inItr += recvLen;
					std::string data(buf, recvLen);
					delete[] buf;
					buf = NULL;

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

					break;
				}
			}
		}
		catch (std::exception ex)
		{
			wxThreadEvent *newEvent = new wxThreadEvent;
			newEvent->SetInt(-1);
			newEvent->SetString(wxString(ex.what()) + "\n");
			wxQueueEvent(form, newEvent);
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
		}
		catch (int)
		{
			wxThreadEvent *newEvent = new wxThreadEvent;
			newEvent->SetInt(-1);
			newEvent->SetString("Disconnected while receiving\n");
			wxQueueEvent(form, newEvent);
		}
		catch (...)
		{
		}
		try
		{
			if (buf != NULL)
				delete[] buf;
		}
		catch (...)
		{
		}
	}
	return NULL;
}
