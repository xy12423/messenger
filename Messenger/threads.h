#pragma once

#ifndef _H_THRD
#define _H_THRD

class pingThread :public wxThread
{
public:
	pingThread() : wxThread(wxTHREAD_DETACHED){};
protected:
	ExitCode Entry();
};

struct msgTask
{
	msgTask(){ uID = -1; }
	msgTask(int _uID, std::string &_msg){ uID = _uID; msg = _msg; }
	int uID;
	std::string msg;
};

class msgThread :public wxThread
{
public:
	msgThread() : wxThread(wxTHREAD_DETACHED){};
	wxMessageQueue<msgTask> taskQue;
protected:
	ExitCode Entry();
};

struct fileSendTask
{
	fileSendTask(){ uID = -1; }
	fileSendTask(int _uID, const fs::path &_path){ uID = _uID; path = _path; }
	int uID;
	fs::path path;
};

class fileSendThread :public wxThread
{
public:
	fileSendThread() : wxThread(wxTHREAD_DETACHED){};
	wxMessageQueue<fileSendTask> taskQue;
protected:
	ExitCode Entry();
};

class recvThread :public wxThread
{
public:
	recvThread() : wxThread(wxTHREAD_DETACHED){};
	wxMessageQueue<int> taskQue;
protected:
	ExitCode Entry();
};

extern volatile int onDelID;

#endif
