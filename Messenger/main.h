#pragma once

#ifndef _H_MAIN
#define _H_MAIN

wxDECLARE_EVENT(wxEVT_COMMAND_THREAD_MSG, wxThreadEvent);

#include "threads.h"

class mainFrame : public wxFrame
{
public:
	mainFrame(const wxString& title);
	enum itemID{
		ID_FRAME,
		ID_LISTUSER, ID_BUTTONADD, ID_BUTTONDEL,
		ID_TEXTMSG, ID_TEXTINPUT, ID_BUTTONSEND, ID_BUTTONSENDFILE,
		ID_TEXTINFO,
		ID_SOCKETLISTENER, ID_SOCKETDATA,
		ID_SOCKETBEGIN_C1, ID_SOCKETBEGIN_C2, ID_SOCKETBEGIN_S1, ID_SOCKETBEGIN_S2
	};

	wxPanel *panel;

	wxListBox *listUser;
	wxButton *buttonAdd, *buttonDel;
	void listUser_SelectedIndexChanged(wxCommandEvent& event);
	void buttonAdd_Click(wxCommandEvent& event);
	void buttonDel_Click(wxCommandEvent& event);

	wxTextCtrl *textMsg, *textInput;
	wxButton *buttonSend, *buttonSendFile;
	void buttonSend_Click(wxCommandEvent& event);
	void buttonSendFile_Click(wxCommandEvent& event);

	wxSocketServer *socketListener;
	void socketListener_Notify(wxSocketEvent& event);
	void socketBeginC1_Notify(wxSocketEvent& event);
	void socketBeginC2_Notify(wxSocketEvent& event);
	void socketBeginS1_Notify(wxSocketEvent& event);
	void socketBeginS2_Notify(wxSocketEvent& event);
	void socketData_Notify(wxSocketEvent& event);
	void newReq();
	void newCon(wxIPV4address addr);

	wxTextCtrl *textInfo;
	void thread_Message(wxThreadEvent& event);

	const int portListener = 4826, portConnect = 4827;

	wxDECLARE_EVENT_TABLE();
};

class MyApp : public wxApp
{
public:
	virtual bool OnInit();
	virtual int OnExit();
};

#endif
