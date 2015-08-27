#include "stdafx.h"
#include "global.h"
#include "session.h"
#include "threads.h"
#include "main.h"

wxBEGIN_EVENT_TABLE(mainFrame, wxFrame)

EVT_LISTBOX(ID_LISTUSER, mainFrame::listUser_SelectedIndexChanged)

EVT_BUTTON(ID_BUTTONADD, mainFrame::buttonAdd_Click)
EVT_BUTTON(ID_BUTTONDEL, mainFrame::buttonDel_Click)

EVT_BUTTON(ID_BUTTONSEND, mainFrame::buttonSend_Click)
EVT_BUTTON(ID_BUTTONSENDFILE, mainFrame::buttonSendFile_Click)

EVT_THREAD(wxID_ANY, mainFrame::thread_Message)

EVT_CLOSE(mainFrame::mainFrame_Close)

wxEND_EVENT_TABLE()

#ifdef __WXMSW__
#define _GUI_SIZE_X 620
#define _GUI_SIZE_Y 560
#else
#define _GUI_SIZE_X 600
#define _GUI_SIZE_Y 540
#endif

mainFrame *form;

fileSendThread *threadFileSend;

server* srv;
std::unordered_map<int, user_ext_data> user_ext;
wx_srv_interface inter;
net::io_service main_io_service;
iosrvThread *threadNetwork;

#define checkErr(x) if (dataItr + (x) > dataEnd) throw(0)
#define read_uint(x)											\
	checkErr(size_uint);										\
	memcpy(reinterpret_cast<char*>(&(x)), dataItr, size_uint);	\
	dataItr += size_uint

void wx_srv_interface::on_data(id_type id, const std::string &data)
{
	try
	{
		const char *dataItr = data.data(), *dataEnd = data.data() + data.size();
		const size_t size_uint = sizeof(unsigned int) / sizeof(char);
		user_ext_data &usr = user_ext.at(id);

		byte type;
		checkErr(1);
		type = *dataItr;
		dataItr += 1;
		switch (type)
		{
			case 1:
			{
				if (frm == nullptr)
					throw(0);

				unsigned int sizeRecv;
				read_uint(sizeRecv);

				checkErr(sizeRecv);
				std::string msg_utf8(dataItr, sizeRecv);
				dataItr += sizeRecv;

				user_ext_data &ext = user_ext[id];
				wxString msg(ext.addr + ':' + wxConvUTF8.cMB2WC(msg_utf8.c_str()) + '\n');
				ext.log.append(msg);
				if (frm->listUser->GetSelection() != -1)
				{
					std::list<int>::iterator itr = frm->userIDs.begin();
					for (int i = frm->listUser->GetSelection(); i > 0; itr++)i--;
					if (id == *itr)
						frm->textMsg->AppendText(msg);
					else
						frm->textInfo->AppendText("Received message from " + ext.addr + "\n");
				}
				else
					frm->textInfo->AppendText("Received message from " + ext.addr + "\n"); 

				break;
			}
			case 2:
			{
				unsigned int recvLE;
				read_uint(recvLE);
				unsigned int blockCount = wxUINT32_SWAP_ON_BE(static_cast<unsigned int>(recvLE));

				read_uint(recvLE);
				unsigned int fNameLen = wxUINT32_SWAP_ON_BE(static_cast<unsigned int>(recvLE));

				std::wstring fName;
				{
					size_t tmp;
					checkErr(fNameLen);
					wxWCharBuffer wbuf = wxConvUTF8.cMB2WC(dataItr, fNameLen, &tmp);
					dataItr += fNameLen;
					fName = std::wstring(wbuf, tmp);
				}

				if (fs::exists(fName))
				{
					int i;
					for (i = 0; i < INT_MAX; i++)
					{
						if (!fs::exists(fs::path(fName + "_" + std::to_string(i))))
							break;
					}
					if (i == INT_MAX)
						throw(std::runtime_error("Failed to open file"));
					fName = fName + "_" + std::to_string(i);
				}
				usr.recvFile = wxConvLocal.cWC2MB(fName.c_str());
				usr.blockLast = blockCount;
				std::cout << "Receiving file " << fName << " from " << usr.addr << std::endl;

				break;
			}
			case 3:
			{
				unsigned int recvLE;
				read_uint(recvLE);
				unsigned int recvLen = wxUINT32_SWAP_ON_BE(static_cast<unsigned int>(recvLE));

				checkErr(recvLen);

				if (usr.blockLast > 0)
				{
					std::ofstream fout(usr.recvFile, std::ios::out | std::ios::binary | std::ios::app);
					fout.write(dataItr, recvLen);
					dataItr += recvLen;
					fout.close();
					usr.blockLast--;
					
					std::cout << usr.recvFile << ":" << usr.blockLast << " block(s) last" << std::endl;
					
					if (usr.blockLast == 0)
						usr.recvFile.clear();
				}

				break;
			}
		}
	}
	catch (std::exception ex)
	{
		std::cerr << ex.what() << std::endl;
	}
	catch (int)
	{
	}
	catch (...)
	{
		throw;
	}
}

#undef checkErr
#undef read_uint

void wx_srv_interface::on_join(id_type id)
{
	if (frm == nullptr)
		return;
	user_ext_data &ext = user_ext.emplace(id, user_ext_data()).first->second;
	std::string addr = srv->get_session(id)->get_address();
	ext.addr = wxConvLocal.cMB2WC(addr.c_str());

	frm->listUser->Append(ext.addr);
	if (frm->listUser->GetSelection() == -1)
		frm->listUser->SetSelection(frm->listUser->GetCount() - 1);
	frm->userIDs.push_back(id);
}

void wx_srv_interface::on_leave(id_type id)
{
	if (frm == nullptr)
		return;
	int i = 0;
	std::list<int>::iterator itr = frm->userIDs.begin(), itrEnd = frm->userIDs.end();
	for (; itr != itrEnd && *itr != id; itr++)i++;
	if (frm->listUser->GetSelection() == i)
		frm->textMsg->SetValue(wxEmptyString);
	frm->listUser->Delete(i);
	frm->userIDs.erase(itr);
	user_ext.erase(id);
}

mainFrame::mainFrame(const wxString& title)
	: wxFrame(NULL, ID_FRAME, title, wxDefaultPosition, wxSize(_GUI_SIZE_X, _GUI_SIZE_Y))
{
	Center();

	panel = new wxPanel(this);
	wxStaticText *label;

	label = new wxStaticText(panel, wxID_ANY,
		wxT("User list"),
		wxPoint(12, 12),
		wxSize(162, 21)
		);
	listUser = new wxListBox(panel, ID_LISTUSER,
		wxPoint(12, 39),
		wxSize(162, 276),
		wxArrayString()
		);
	buttonAdd = new wxButton(panel, ID_BUTTONADD,
		wxT("Connect to"),
		wxPoint(12, 321),
		wxSize(162, 42)
		);
	buttonDel = new wxButton(panel, ID_BUTTONDEL,
		wxT("Disconnect"),
		wxPoint(12, 369),
		wxSize(162, 42)
		);

	textMsg = new wxTextCtrl(panel, ID_TEXTMSG,
		wxEmptyString,
		wxPoint(180, 12),
		wxSize(412, 303),
		wxTE_MULTILINE | wxTE_READONLY
		);
	textInput = new wxTextCtrl(panel, ID_TEXTINPUT,
		wxEmptyString,
		wxPoint(180, 321),
		wxSize(340, 90),
		wxTE_MULTILINE
		);
	buttonSend = new wxButton(panel, ID_BUTTONSEND,
		wxT("Send"),
		wxPoint(526, 321),
		wxSize(66, 42)
		);
	buttonSendFile = new wxButton(panel, ID_BUTTONSENDFILE,
		wxT("Send File"),
		wxPoint(526, 369),
		wxSize(66, 42)
		);

	textInfo = new wxTextCtrl(panel, ID_TEXTINFO,
		wxEmptyString,
		wxPoint(12, 417),
		wxSize(580, 92),
		wxTE_MULTILINE | wxTE_READONLY
		);

	threadFileSend = new fileSendThread();
	if (threadFileSend->Run() != wxTHREAD_NO_ERROR)
	{
		delete threadFileSend;
		throw(std::runtime_error("Can't create fileSendThread"));
	}

	textStrm = new textStream(textInfo);
	cout_orig = std::cout.rdbuf();
	std::cout.rdbuf(textStrm);
	cerr_orig = std::cerr.rdbuf();
	std::cerr.rdbuf(textStrm);
}

void mainFrame::listUser_SelectedIndexChanged(wxCommandEvent& event)
{
	std::list<int>::iterator itr = userIDs.begin();
	for (int i = listUser->GetSelection(); i > 0; i--)itr++;
	int uID = *itr;
	textMsg->SetValue(user_ext[uID].log);
	textMsg->ShowPosition(user_ext[uID].log.size());
}

void mainFrame::buttonAdd_Click(wxCommandEvent& event)
{
	try
	{
		wxTextEntryDialog inputDlg(this, wxT("Please input address"));
		inputDlg.ShowModal();
		wxString addrStr = inputDlg.GetValue();
		if (addrStr != wxEmptyString)
		{
			srv->connect(addrStr.ToStdString());
		}
	}
	catch (std::exception ex)
	{
		textInfo->AppendText(ex.what() + std::string("\n"));
	}
}

void mainFrame::buttonDel_Click(wxCommandEvent& event)
{
	int selection = listUser->GetSelection();
	if (selection != -1)
	{
		std::list<int>::iterator itr = userIDs.begin();
		for (int i = selection; i > 0; itr++)i--;

		srv->disconnect(*itr);
	}
}

void mainFrame::buttonSend_Click(wxCommandEvent& event)
{
	wxString msg = textInput->GetValue();
	if (!msg.empty())
	{
		textInput->SetValue(wxEmptyString);
		if (listUser->GetSelection() != -1)
		{
			wxCharBuffer buf = wxConvUTF8.cWC2MB(msg.c_str());
			std::string msgutf8(buf, buf.length());
			std::list<int>::iterator itr = userIDs.begin();
			for (int i = listUser->GetSelection(); i > 0; itr++)i--;
			int uID = *itr;
			insLen(msgutf8);
			msgutf8.insert(0, "\x01");
			srv->send_data(uID, msgutf8, wxT(""));
			textMsg->AppendText("Me:" + msg + '\n');
			user_ext[uID].log.append("Me:" + msg + '\n');
		}
	}
}

void mainFrame::buttonSendFile_Click(wxCommandEvent& event)
{
	wxFileDialog fileDlg(this);
	fileDlg.ShowModal();
	std::wstring path = fileDlg.GetPath().ToStdWstring();
	if ((!path.empty()) && fs::exists(path))
	{
		if (listUser->GetSelection() != -1)
		{
			std::list<int>::iterator itr = userIDs.begin();
			for (int i = listUser->GetSelection(); i > 0; itr++)i--;
			int uID = *itr;
			threadFileSend->taskQue.Post(fileSendTask(uID, fs::path(path)));
		}
	}
}

void mainFrame::thread_Message(wxThreadEvent& event)
{
	
}

void mainFrame::mainFrame_Close(wxCloseEvent& event)
{
	try
	{
		std::cout.rdbuf(cout_orig);
		std::cerr.rdbuf(cerr_orig);
		delete textStrm;

		inter.set_frame(nullptr);
	}
	catch (std::exception ex)
	{
		wxMessageBox(ex.what(), wxT("Error"), wxOK | wxICON_ERROR);
	}
	wxFrame::OnCloseWindow(event);
}

IMPLEMENT_APP(MyApp)

bool MyApp::OnInit()
{
	try
	{
		threadNetwork = new iosrvThread(main_io_service);
		if (threadNetwork->Run() != wxTHREAD_NO_ERROR)
		{
			delete threadNetwork;
			throw(std::runtime_error("Can't create iosrvThread"));
		}
		srv = new server(main_io_service, &inter, net::ip::tcp::endpoint(net::ip::tcp::v4(), portListener));

		form = new mainFrame(wxT("Messenger"));
		inter.set_frame(form);
		form->Show();
	}
	catch (std::exception ex)
	{
		wxMessageBox(ex.what(), wxT("Error"), wxOK | wxICON_ERROR);
		return false;
	}

	return true;
}

int MyApp::OnExit()
{
	try
	{
		threadFileSend->Delete();

		threadNetwork->iosrv_work.reset();
		threadNetwork->iosrv.stop();
		threadNetwork->Delete();

		delete srv;
	}
	catch (...)
	{
		return 1;
	}

	return 0;
}
