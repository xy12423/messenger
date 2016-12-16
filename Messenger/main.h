#pragma once

#ifndef _H_MAIN
#define _H_MAIN

#include "threads.h"

typedef std::function<void()> gui_callback;

class textStream;

class mainFrame : public wxFrame
{
public:
	mainFrame(const wxString& title);

	friend class wx_srv_interface;
private:
	enum itemID{
		ID_FRAME,
		ID_LABELLISTUSER, ID_LISTUSER, ID_BUTTONADD, ID_BUTTONDEL,
		ID_TEXTMSG, ID_TEXTINPUT, ID_BUTTONSEND, ID_BUTTONSENDIMAGE, ID_BUTTONSENDFILE, ID_BUTTONCANCELSEND,
		ID_TEXTINFO
	};

	wxPanel *panel;

	wxStaticText *labelListUser;
	wxListBox *listUser;
	wxButton *buttonAdd, *buttonDel;
	void listUser_SelectedIndexChanged(wxCommandEvent& event);
	void buttonAdd_Click(wxCommandEvent& event);
	void buttonDel_Click(wxCommandEvent& event);

	wxRichTextCtrl *textMsg;
	wxTextCtrl *textInput;
	wxButton *buttonSend, *buttonSendImage, *buttonSendFile, *buttonCancelSend;
	void buttonSend_Click(wxCommandEvent& event);
	void buttonSendImage_Click(wxCommandEvent& event);
	void buttonSendFile_Click(wxCommandEvent& event);
	void buttonCancelSend_Click(wxCommandEvent& event);

	void thread_Message(wxThreadEvent& event);

	void mainFrame_Resize(wxSizeEvent& event);
	void mainFrame_Close(wxCloseEvent& event);

	wxTextCtrl *textInfo;
	std::unique_ptr<textStream> textStrm;
	std::streambuf *cout_orig, *cerr_orig;

	std::vector<user_id_type> userIDs;

	wxDECLARE_EVENT_TABLE();
};

class textStream : public std::streambuf
{
public:
	textStream(mainFrame *_frm, wxTextCtrl *_text) :frm(_frm), text(_text) {};

protected:
	int_type overflow(int_type c)
	{
		buf.push_back(static_cast<char>(c));
		if (c == '\n')
		{
			std::string _buf = std::move(buf);
			buf.clear();

			wxThreadEvent *newEvent = new wxThreadEvent;
			newEvent->SetPayload<gui_callback>([this, _buf]() { text->AppendText(_buf); });
			wxQueueEvent(frm, newEvent);
		}
		return c;
	}
private:
	mainFrame *frm;
	wxTextCtrl *text;
	std::string buf;
};

extern const char* IMG_TMP_PATH_NAME;
extern const char* IMG_TMP_FILE_NAME;
const size_t IMAGE_SIZE_LIMIT = 0x400000;

//Exceptions that can be safely ignored
class wx_srv_interface_error :public std::runtime_error
{
public:
	wx_srv_interface_error() :std::runtime_error("Error in wx_srv_interface") {};
};

class wx_srv_interface :public msgr_proto::server
{
public:
	wx_srv_interface(asio::io_service& _main_io_service,
		asio::io_service& _misc_io_service,
		asio::ip::tcp::endpoint _local_endpoint,
		crypto::server& _crypto_srv);
	~wx_srv_interface();

	virtual void on_data(user_id_type id, const std::string& data);

	virtual void on_join(user_id_type id, const std::string& key);
	virtual void on_leave(user_id_type id);

	virtual bool new_rand_port(port_type& port);
	virtual void free_rand_port(port_type port) { ports.push_back(port); };

	template <typename... _Ty>
	void certify_key(_Ty&&... key) { certifiedKeys.emplace(std::forward<_Ty>(key)...); }

	void set_frame(mainFrame *_frm) { frm = _frm; }
	void set_static_port(port_type port) { static_port = port; };
	void new_image_id(int& id) { id = image_id; image_id++; }
private:
	std::unordered_map<std::string, std::string> certifiedKeys;
	std::list<port_type> ports;
	int static_port = -1;

	int image_id = 0;

	mainFrame *frm;
};

class MyApp : public wxApp
{
public:
	virtual bool OnInit();
	virtual int OnExit();
private:
	mainFrame *form;
};

struct plugin_info_type
{
	typedef void(*virtual_msg_handler_ptr)(uint16_t virtual_user_id, const char* data, uint32_t size);

	std::string name;
	plugin_id_type plugin_id;
	std::unordered_set<uint16_t> virtual_user_list;
	virtual_msg_handler_ptr virtual_msg_handler;
};

extern const char* plugin_file_name;

#endif
