#pragma once

#ifndef _H_MAIN
#define _H_MAIN

#include "threads.h"

class textStream : public std::streambuf
{
public:
	textStream(wxTextCtrl *_text) { text = _text; }

protected:
	int_type overflow(int_type c)
	{
		buf.push_back(c);
		if (c == '\n')
		{
			text->AppendText(buf);
			buf.clear();
		}
		return c;
	}
private:
	wxTextCtrl *text;
	std::string buf;
};

class mainFrame : public wxFrame
{
public:
	mainFrame(const wxString& title);

	friend class wx_srv_interface;
private:
	enum itemID{
		ID_FRAME,
		ID_LISTUSER, ID_BUTTONADD, ID_BUTTONDEL,
		ID_TEXTMSG, ID_TEXTINPUT, ID_BUTTONSEND, ID_BUTTONSENDFILE, ID_BUTTONCANCELSEND, ID_BUTTONIMPORTKEY, ID_BUTTONEXPORTKEY,
		ID_TEXTINFO
	};

	wxPanel *panel;

	wxListBox *listUser;
	wxButton *buttonAdd, *buttonDel;
	void listUser_SelectedIndexChanged(wxCommandEvent& event);
	void buttonAdd_Click(wxCommandEvent& event);
	void buttonDel_Click(wxCommandEvent& event);

	wxTextCtrl *textMsg, *textInput;
	wxButton *buttonSend, *buttonSendFile, *buttonCancelSend, *buttonImportKey, *buttonExportKey;
	void buttonSend_Click(wxCommandEvent& event);
	void buttonSendFile_Click(wxCommandEvent& event);
	void buttonCancelSend_Click(wxCommandEvent& event);
	void buttonImportKey_Click(wxCommandEvent& event);
	void buttonExportKey_Click(wxCommandEvent& event);

	void thread_Message(wxThreadEvent& event);

	void mainFrame_Close(wxCloseEvent& event);

	wxTextCtrl *textInfo;
	textStream *textStrm;
	std::streambuf *cout_orig, *cerr_orig;

	std::vector<int> userIDs;

	wxDECLARE_EVENT_TABLE();
};

class wx_srv_interface :public server_interface
{
public:
	virtual void on_data(user_id_type id, const std::string &data);

	virtual void on_join(user_id_type id);
	virtual void on_leave(user_id_type id);

	virtual void on_unknown_key(user_id_type id, const std::string& key);

	virtual bool new_rand_port(port_type &port);
	virtual void free_rand_port(port_type port) { ports.push_back(port); };

	void set_frame(mainFrame *_frm) { frm = _frm; }
private:
	std::unordered_set<iosrvThread*> threads;
	std::list<port_type> ports;

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
	typedef void(*virtual_msg_handler_ptr)(uint16_t virtual_user_id, const char* data, uint32_t length);

	std::string name;
	plugin_id_type plugin_id;
	std::unordered_set<uint16_t> virtual_user_list;
	virtual_msg_handler_ptr virtual_msg_handler;
};

extern const char* plugin_file_name;

#endif
