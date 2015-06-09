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

struct sendTask
{
	sendTask(){ uID = -1; }
	sendTask(int _uID, const std::string &_data, const wxString &_msg) :
		data(_data), msg(_msg)
	{ uID = _uID; }
	int uID;
	std::string data;
	wxString msg;
};

class sendThread :public wxThread
{
public:
	sendThread() : wxThread(wxTHREAD_DETACHED){};
	wxMessageQueue<sendTask> taskQue;
protected:
	ExitCode Entry();
};

struct msgSendTask
{
	msgSendTask(){ uID = -1; }
	msgSendTask(int _uID, const std::string &_msg):
		msg(_msg)
	{ uID = _uID; }
	int uID;
	std::string msg;
};

class msgSendThread :public wxThread
{
public:
	msgSendThread() : wxThread(wxTHREAD_DETACHED){};
	wxMessageQueue<msgSendTask> taskQue;
protected:
	ExitCode Entry();
};

struct fileSendTask
{
	fileSendTask(){ uID = -1; }
	fileSendTask(int _uID, const fs::path &_path):
		path(_path)
	{ uID = _uID; }
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
