#pragma once

#ifndef _H_THRD
#define _H_THRD

class iosrvThread :public wxThread
{
public:
	iosrvThread(asio::io_service& _iosrv) : wxThread(wxTHREAD_DETACHED), iosrv(_iosrv) {};
	wxThreadError Delete(ExitCode *rc = NULL, wxThreadWait waitMode = wxTHREAD_WAIT_DEFAULT) { stop(); return wxThread::Delete(); };

	void stop() { iosrv_work.reset(); iosrv.stop(); }
protected:
	asio::io_service& iosrv;
	std::shared_ptr<asio::io_service::work> iosrv_work;

	ExitCode Entry();
};

struct fileSendTask
{
	fileSendTask(user_id_type _uID, const fs::path& path)
		:fileName(path.wstring()), uID(_uID),
		fin(path.string(), std::ios_base::in | std::ios_base::binary)
	{}
	user_id_type uID;
	std::wstring fileName;
	std::ifstream fin;
	data_size_type blockCount = 1, blockCountAll;
};

class fileSendThread :public wxThread
{
public:
	fileSendThread(msgr_proto::server& _srv) : wxThread(wxTHREAD_DETACHED), srv(_srv), block(std::make_unique<char[]>(fileBlockLen)) {}
	wxThreadError Delete(ExitCode *rc = NULL, wxThreadWait waitMode = wxTHREAD_WAIT_DEFAULT) { stop_thread(); return wxThread::Delete(); }
	
	void start(user_id_type uID, const fs::path& path);
	void stop(user_id_type uID);

	void stop_thread() { iosrv_work.reset(); iosrv.stop(); }

	void write();

	static const int fileBlockLen = 0x80000;
protected:
	ExitCode Entry();
private:
	std::list<fileSendTask> tasks;
	
	std::unique_ptr<char[]> block;

	asio::io_service iosrv;
	msgr_proto::server &srv;
	std::shared_ptr<asio::io_service::work> iosrv_work;
};

struct user_ext_type
{
	std::wstring addr;
	struct log_type
	{
		log_type(const char* _msg) :is_image(false), msg(_msg) {}
		log_type(const std::string& _msg) :is_image(false), msg(_msg) {}
		log_type(const wxString& _msg) :is_image(false), msg(_msg) {}
		log_type(const fs::path& _image) :is_image(true), image(_image) {}

		bool is_image;
		wxString msg;
		fs::path image;
	};
	std::list<log_type> log;

	std::string recvFile;
	int blockLast;

	bool isVirtual = false;
};

enum pac_type {
	PAC_TYPE_MSG,
	PAC_TYPE_FILE_H,
	PAC_TYPE_FILE_B,
	PAC_TYPE_IMAGE,
};

#endif
