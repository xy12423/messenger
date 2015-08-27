#pragma once

#ifndef _H_THRD
#define _H_THRD

class iosrvThread :public wxThread
{
public:
	iosrvThread(net::io_service& _iosrv) : wxThread(wxTHREAD_DETACHED), iosrv(_iosrv) {};

	net::io_service& iosrv;
	std::shared_ptr<net::io_service::work> iosrv_work;
protected:
	ExitCode Entry();
};

struct fileSendTask
{
	fileSendTask() { uID = -1; }
	fileSendTask(int _uID, const fs::path &_path) :
		path(_path)
	{
		uID = _uID;
	}
	int uID;
	fs::path path;
};

class fileSendThread :public wxThread
{
public:
	fileSendThread() : wxThread(wxTHREAD_DETACHED) {};
	wxMessageQueue<fileSendTask> taskQue;
protected:
	ExitCode Entry();
};

#endif
