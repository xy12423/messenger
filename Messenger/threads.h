#pragma once

#ifndef _H_THRD
#define _H_THRD

class iosrvThread :public wxThread
{
public:
	iosrvThread(asio::io_service& _iosrv) : wxThread(wxTHREAD_DETACHED), iosrv(_iosrv) {};

	void stop() { iosrv_work.reset(); iosrv.stop(); }
protected:
	asio::io_service& iosrv;
	std::shared_ptr<asio::io_service::work> iosrv_work;

	ExitCode Entry();
};

struct fileSendTask
{
	fileSendTask() { uID = -1; }
	fileSendTask(int _uID, const fs::path &path)
		:fileName(path.wstring()),
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
	
	const int fileBlockLen = 0x80000;
	std::unique_ptr<char[]> block = std::make_unique<char[]>(fileBlockLen);

	asio::io_service iosrv;
	std::shared_ptr<asio::io_service::work> iosrv_work;
};

struct user_ext_type
{
	std::wstring addr;
	wxString log;

	std::string recvFile;
	int blockLast;

	bool isVirtual = false;
};

static const uint8_t pac_type_msg = 0x00;
static const uint8_t pac_type_file_h = 0x01;
static const uint8_t pac_type_file_b = 0x02;

#endif
