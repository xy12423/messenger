#pragma once

#ifndef _H_THRD
#define _H_THRD

class iosrvThread :public wxThread
{
public:
	iosrvThread(net::io_service& _iosrv) : wxThread(wxTHREAD_DETACHED), iosrv(_iosrv) {};

	void stop() { iosrv_work.reset(); iosrv.stop(); }
protected:
	net::io_service& iosrv;
	std::shared_ptr<net::io_service::work> iosrv_work;

	ExitCode Entry();
};

struct fileSendTask
{
	fileSendTask() { uID = -1; }
	fileSendTask(int _uID, const fs::path &path):
		fileName(path.wstring()),
		fin(path.string(), std::ios_base::in | std::ios_base::binary)
	{
		uID = _uID;
	}
	int uID;
	std::wstring fileName;
	std::ifstream fin;
	data_length_type blockCount = 1, blockCountAll;
};

class fileSendThread :public wxThread
{
public:
	fileSendThread() : wxThread(wxTHREAD_DETACHED) {};
	
	void start(int uID, const fs::path &path);
	void stop(int uID);

	void stop_thread() { iosrv_work.reset(); iosrv.stop(); }

	void write();

protected:
	ExitCode Entry();
private:
	std::list<fileSendTask> tasks;

	net::io_service iosrv;
	std::shared_ptr<net::io_service::work> iosrv_work;
};

#endif
