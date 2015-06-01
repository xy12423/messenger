#pragma once

#ifndef _H_THRD
#define _H_THRD

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

struct fileTask
{
	fileTask(){ uID = -1; }
	fileTask(int _uID, const fs::path &_path){ uID = _uID; path = _path; }
	int uID;
	fs::path path;
};

class fileThread :public wxThread
{
public:
	fileThread() : wxThread(wxTHREAD_DETACHED){};
	wxMessageQueue<fileTask> taskQue;
protected:
	ExitCode Entry();
};

class pingThread :public wxThread
{
public:
	pingThread() : wxThread(wxTHREAD_DETACHED){};
protected:
	ExitCode Entry();
};

extern volatile int onDelID;

#endif
