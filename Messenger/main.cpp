#include "stdafx.h"
#include "crypto.h"
#include "global.h"
#include "threads.h"
#include "main.h"

wxBEGIN_EVENT_TABLE(mainFrame, wxFrame)

EVT_LISTBOX(ID_LISTUSER, mainFrame::listUser_SelectedIndexChanged)

EVT_BUTTON(ID_BUTTONADD, mainFrame::buttonAdd_Click)
EVT_BUTTON(ID_BUTTONDEL, mainFrame::buttonDel_Click)

EVT_BUTTON(ID_BUTTONSEND, mainFrame::buttonSend_Click)
EVT_BUTTON(ID_BUTTONSENDFILE, mainFrame::buttonSendFile_Click)

EVT_SOCKET(ID_SOCKETLISTENER, mainFrame::socketListener_Notify)
EVT_SOCKET(ID_SOCKETBEGIN_S1, mainFrame::socketBeginS1_Notify)
EVT_SOCKET(ID_SOCKETBEGIN_S2, mainFrame::socketBeginS2_Notify)
EVT_SOCKET(ID_SOCKETBEGIN_C1, mainFrame::socketBeginC1_Notify)
EVT_SOCKET(ID_SOCKETBEGIN_C2, mainFrame::socketBeginC2_Notify)
EVT_SOCKET(ID_SOCKETDATA, mainFrame::socketData_Notify)

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
userList users;
int nextID = 0;
std::list<int> userIDs;
std::list<int> ports;
std::string e0str;

pingThread *threadPing;
sendThread *threadSend;
msgSendThread *threadMsgSend;
fileSendThread *threadFileSend;
recvThread *threadRecv;

int newPort()
{
	if (ports.empty())
		return -1;
	std::list<int>::iterator portItr = ports.begin();
	for (int i = std::rand() % ports.size(); i > 0; i--)
		portItr++;
	int port = *portItr;
	ports.erase(portItr);
	return port;
}

void freePort(unsigned short port)
{
	ports.push_back(port);
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

	wxIPV4address localAddr;
	localAddr.AnyAddress();
	if (!localAddr.Service(portListener))
		throw(std::runtime_error("Failed to set port"));
	socketListener = new wxSocketServer(localAddr);
	if (!socketListener->Ok())
	{
		throw(std::runtime_error("Socket:Error"));
	}
	socketListener->SetEventHandler(*this, ID_SOCKETLISTENER);
	socketListener->SetNotify(wxSOCKET_CONNECTION_FLAG | wxSOCKET_LOST_FLAG);
	socketListener->Notify(true);

	threadPing = new pingThread();
	if (threadPing->Run() != wxTHREAD_NO_ERROR)
	{
		delete threadPing;
		throw(std::runtime_error("Can't create fileThread"));
	}
	threadSend = new sendThread();
	if (threadSend->Run() != wxTHREAD_NO_ERROR)
	{
		delete threadSend;
		throw(std::runtime_error("Can't create msgThread"));
	}
	threadMsgSend = new msgSendThread();
	if (threadMsgSend->Run() != wxTHREAD_NO_ERROR)
	{
		delete threadMsgSend;
		throw(std::runtime_error("Can't create msgThread"));
	}
	threadFileSend = new fileSendThread();
	if (threadFileSend->Run() != wxTHREAD_NO_ERROR)
	{
		delete threadFileSend;
		throw(std::runtime_error("Can't create fileSendThread"));
	}
	threadRecv = new recvThread();
	if (threadRecv->Run() != wxTHREAD_NO_ERROR)
	{
		delete threadRecv;
		throw(std::runtime_error("Can't create recvThread"));
	}
}

void mainFrame::listUser_SelectedIndexChanged(wxCommandEvent& event)
{
	std::list<int>::iterator itr = userIDs.begin();
	for (int i = listUser->GetSelection(); i > 0; i--)itr++;
	int uID = *itr;
	textMsg->SetValue(users[uID].log);
	textMsg->ShowPosition(users[uID].log.size());
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
			wxIPV4address addr;
			if (!addr.Hostname(addrStr))
				wxMessageBox(wxT("Invalid IP"), wxT("Error"), wxOK | wxICON_ERROR);
			else
			{
				addr.Service(portListener);
				newCon(addr);
			}
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
		user &usr = users[*itr];

		onDelID = *itr;
		wxIPV4address localAddr;
		usr.con->GetLocal(localAddr);
		freePort(localAddr.Service());
		usr.con->Destroy();
		int i = 0;
		textMsg->SetValue(wxEmptyString);
		users.erase(*itr);
		userIDs.erase(itr);
		listUser->Delete(selection);
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
			threadMsgSend->taskQue.Post(msgSendTask(uID, msgutf8));
			textMsg->AppendText("Me:" + msg + '\n');
			users[uID].log.append("Me:" + msg + '\n');
		}
	}
}

void mainFrame::buttonSendFile_Click(wxCommandEvent& event)
{
	wxFileDialog fileDlg(this);
	fileDlg.ShowModal();
	std::wstring path = fileDlg.GetPath();
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

void mainFrame::socketListener_Notify(wxSocketEvent& event)
{
	try
	{
		switch (event.GetSocketEvent())
		{
			case wxSOCKET_CONNECTION:
				newReq();
				break;
		}
	}
	catch (std::exception ex)
	{
		textInfo->AppendText(ex.what() + std::string("\n"));
	}
}

void mainFrame::newReq()
{
	wxSocketBase *tempCon = socketListener->Accept(false);
	try
	{
		tempCon->SetFlags(wxSOCKET_WAITALL);
		wxSocketServer *newCon;
		int port;

		while (true)
		{
			port = newPort();
			if (port == -1)
				throw(std::runtime_error("Socket:No port available"));
			wxIPV4address localAddr;
			localAddr.AnyAddress();
			if (!localAddr.Service(port))
				continue;
			newCon = new wxSocketServer(localAddr, wxSOCKET_WAITALL);
			if (!newCon->Ok())
			{
				wxSocketError err = newCon->LastError();
				newCon->Destroy();
				switch (err)
				{
					case wxSOCKET_INVADDR:
						throw(std::runtime_error("Socket:Invalid address"));
					case wxSOCKET_INVPORT:
						continue;
					case wxSOCKET_MEMERR:
						throw(std::runtime_error("Socket:Memory exhausted"));
					default:
						throw(std::runtime_error("Socket:Error"));
				}
			}
			else
				break;
		}
		newCon->SetEventHandler(*this, ID_SOCKETBEGIN_S1);
		newCon->SetNotify(wxSOCKET_CONNECTION_FLAG | wxSOCKET_LOST_FLAG);
		newCon->Notify(true);

		unsigned short portSend = wxUINT16_SWAP_ON_BE(static_cast<unsigned short>(port));
		tempCon->Write(&portSend, sizeof(unsigned short) / sizeof(char));
		tempCon->Destroy();
	}
	catch (...)
	{
		tempCon->Destroy();
		throw;
	}
}

void mainFrame::newCon(wxIPV4address addr)
{
	wxSocketClient *con = new wxSocketClient(wxSOCKET_WAITALL);
	wxIPV4address localAddr;
	localAddr.AnyAddress();
	localAddr.Service(portConnect);
	con->SetEventHandler(*this, ID_SOCKETBEGIN_C1);
	con->SetNotify(wxSOCKET_INPUT_FLAG | wxSOCKET_LOST_FLAG);
	con->Notify(true);
	con->Connect(addr, localAddr, false);
}

void mainFrame::socketBeginS1_Notify(wxSocketEvent& event)
{
	wxSocketBase *newCon = NULL;
	try
	{
		switch (event.GetSocketEvent())
		{
			case wxSOCKET_CONNECTION:
			{
				wxSocketServer *servCon = dynamic_cast<wxSocketServer*>(event.GetSocket());
				if (servCon == NULL)
					throw(std::runtime_error("Not a server socket"));
				newCon = servCon->Accept(false);
				newCon->SetFlags(wxSOCKET_WAITALL);
				newCon->SetEventHandler(*this, ID_SOCKETBEGIN_S2);
				newCon->SetNotify(wxSOCKET_INPUT_FLAG | wxSOCKET_LOST_FLAG);
				newCon->Notify(true);
				newCon->Write(e0str.c_str(), e0str.size());

				servCon->Destroy();
				break;
			}
			case wxSOCKET_LOST:
				event.GetSocket()->Destroy();
				break;
		}
	}
	catch (std::exception ex)
	{
		textInfo->AppendText(ex.what() + std::string("\n"));
		event.GetSocket()->Destroy();
		if (newCon != NULL)
			newCon->Destroy();
	}
}

void mainFrame::socketBeginS2_Notify(wxSocketEvent& event)
{
	try
	{
		switch (event.GetSocketEvent())
		{
			case wxSOCKET_INPUT:
			{
				unsigned short sizeRecvLE;
				wxSocketBase *socket = event.GetSocket();
				socket->SetEventHandler(*this, ID_SOCKETDATA);
				socket->SetNotify(wxSOCKET_INPUT_FLAG | wxSOCKET_LOST_FLAG);
				socket->Notify(true);

				socket->Read(&sizeRecvLE, sizeof(unsigned short) / sizeof(char));
				unsigned short sizeRecv = wxUINT16_SWAP_ON_BE(static_cast<unsigned short>(sizeRecvLE));

				char *buf = new char[sizeRecv];
				socket->Read(buf, sizeRecv);
				std::string keyStr(buf, sizeRecv);
				delete[] buf;

				user &item = users.emplace(nextID, user()).first->second;
				userIDs.push_back(nextID);
				item.uID = nextID;
				nextID++;
				if (!socket->GetPeer(item.addr))
					throw(std::runtime_error("Failed to get remote address"));
				item.con = socket;
				CryptoPP::StringSource keySource(keyStr, true);
				item.e1.AccessPublicKey().Load(keySource);
				listUser->Append(item.addr.IPAddress());
				if (listUser->GetSelection() == -1)
					listUser->SetSelection(0);

				socket->SetEventHandler(*this, ID_SOCKETDATA);
				socket->SetFlags(wxSOCKET_WAITALL);
				socket->SetNotify(wxSOCKET_INPUT_FLAG | wxSOCKET_LOST_FLAG);
				socket->Notify(true);

				break;
			}
			case wxSOCKET_LOST:
			{
				switch (event.GetSocket()->LastError())
				{
					case wxSOCKET_INVOP:
						throw(std::runtime_error("Socket:Invalid operation"));
					case wxSOCKET_IOERR:
						throw(std::runtime_error("Socket:IO error"));
					case wxSOCKET_INVSOCK:
						throw(std::runtime_error("Socket:Invalid socket"));
					case wxSOCKET_NOHOST:
						throw(std::runtime_error("Socket:No corresponding host"));
					case wxSOCKET_TIMEDOUT:
						throw(std::runtime_error("Socket:Operation timed out"));
					case wxSOCKET_INVADDR:
						throw(std::runtime_error("Socket:Invalid address"));
					case wxSOCKET_INVPORT:
						throw(std::runtime_error("Socket:Invalid port"));
					case wxSOCKET_MEMERR:
						throw(std::runtime_error("Socket:Memory exhausted"));
					default:
						throw(std::runtime_error("Socket:Error"));
				}
			}
		}
	}
	catch (std::exception ex)
	{
		textInfo->AppendText(ex.what() + std::string("\n"));
		event.GetSocket()->Destroy();
	}
}

void mainFrame::socketBeginC1_Notify(wxSocketEvent& event)
{
	try
	{
		wxSocketClient *newCon = NULL;
		switch (event.GetSocketEvent())
		{
			case wxSOCKET_INPUT:
			{
				unsigned short portRecv;
				wxSocketBase *socket = event.GetSocket();
				wxIPV4address remoteAddr;
				if (!socket->GetPeer(remoteAddr))
					throw(std::runtime_error("Failed to get remote address"));
				socket->Read(&portRecv, sizeof(unsigned short) / sizeof(char));
				unsigned short portRemote = wxUINT16_SWAP_ON_BE(static_cast<unsigned short>(portRecv));
				if (!remoteAddr.Service(portRemote))
					throw(std::runtime_error("Failed to set remote port"));

				int port;
				wxIPV4address localAddr;
				while (true)
				{
					port = newPort();
					if (port == -1)
						throw(std::runtime_error("Socket:No port available"));
					if (localAddr.Service(port))
						break;
				}
				localAddr.AnyAddress();

				wxSocketClient *newCon = new wxSocketClient(wxSOCKET_WAITALL);
				newCon->SetEventHandler(*this, ID_SOCKETBEGIN_C2);
				newCon->SetNotify(wxSOCKET_INPUT_FLAG | wxSOCKET_LOST_FLAG);
				newCon->Notify(true);
				newCon->Connect(remoteAddr, localAddr, false);

				socket->Destroy();

				break;
			}
			case wxSOCKET_LOST:
			{
				switch (event.GetSocket()->LastError())
				{
					case wxSOCKET_INVOP:
						throw(std::runtime_error("Socket:Invalid operation"));
					case wxSOCKET_IOERR:
						throw(std::runtime_error("Socket:IO error"));
					case wxSOCKET_INVSOCK:
						throw(std::runtime_error("Socket:Invalid socket"));
					case wxSOCKET_NOHOST:
						throw(std::runtime_error("Socket:No corresponding host"));
					case wxSOCKET_TIMEDOUT:
						throw(std::runtime_error("Socket:Operation timed out"));
					case wxSOCKET_INVADDR:
						throw(std::runtime_error("Socket:Invalid address"));
					case wxSOCKET_INVPORT:
						throw(std::runtime_error("Socket:Invalid port"));
					case wxSOCKET_MEMERR:
						throw(std::runtime_error("Socket:Memory exhausted"));
					default:
						throw(std::runtime_error("Socket:Connection timed out"));
				}
			}
		}
	}
	catch (std::exception ex)
	{
		textInfo->AppendText(ex.what() + std::string("\n"));
		event.GetSocket()->Destroy();
	}
}

void mainFrame::socketBeginC2_Notify(wxSocketEvent& event)
{
	try
	{
		wxSocketClient *newCon = NULL;
		switch (event.GetSocketEvent())
		{
			case wxSOCKET_INPUT:
			{
				unsigned short sizeRecvLE;
				wxSocketBase *socket = event.GetSocket();
				socket->Read(&sizeRecvLE, sizeof(unsigned short) / sizeof(char));
				unsigned short sizeRecv = wxUINT16_SWAP_ON_BE(static_cast<unsigned short>(sizeRecvLE));

				char *buf = new char[sizeRecv];
				socket->Read(buf, sizeRecv);
				std::string keyStr(buf, sizeRecv);
				delete[] buf;

				user &item = users.emplace(nextID, user()).first->second;
				userIDs.push_back(nextID);
				item.uID = nextID;
				nextID++;
				if (!socket->GetPeer(item.addr))
					throw(std::runtime_error("Failed to get remote address"));
				item.con = socket;
				CryptoPP::StringSource keySource(keyStr, true);
				item.e1.AccessPublicKey().Load(keySource);
				listUser->Append(item.addr.IPAddress());
				if (listUser->GetSelection() == -1)
					listUser->SetSelection(0);

				socket->SetEventHandler(*this, ID_SOCKETDATA);
				socket->SetNotify(wxSOCKET_INPUT_FLAG | wxSOCKET_LOST_FLAG);
				socket->Notify(true);

				socket->Write(e0str.c_str(), e0str.size());

				socket->SetFlags(wxSOCKET_WAITALL);

				break;
			}
			case wxSOCKET_LOST:
			{
				switch (event.GetSocket()->LastError())
				{
					case wxSOCKET_INVOP:
						throw(std::runtime_error("Socket:Invalid operation"));
					case wxSOCKET_IOERR:
						throw(std::runtime_error("Socket:IO error"));
					case wxSOCKET_INVSOCK:
						throw(std::runtime_error("Socket:Invalid socket"));
					case wxSOCKET_NOHOST:
						throw(std::runtime_error("Socket:No corresponding host"));
					case wxSOCKET_TIMEDOUT:
						throw(std::runtime_error("Socket:Operation timed out"));
					case wxSOCKET_INVADDR:
						throw(std::runtime_error("Socket:Invalid address"));
					case wxSOCKET_INVPORT:
						throw(std::runtime_error("Socket:Invalid port"));
					case wxSOCKET_MEMERR:
						throw(std::runtime_error("Socket:Memory exhausted"));
					default:
						throw(std::runtime_error("Socket:Error"));
				}
			}
		}
	}
	catch (std::exception ex)
	{
		textInfo->AppendText(ex.what() + std::string("\n"));
		event.GetSocket()->Destroy();
	}
}

void mainFrame::socketData_Notify(wxSocketEvent& event)
{
	try
	{
		wxSocketBase *con = event.GetSocket();
		switch (event.GetSocketEvent())
		{
			case wxSOCKET_INPUT:
			{
				userList::iterator itr = users.begin(), itrEnd = users.end();
				for (; itr != itrEnd; itr++)
				{
					if (itr->second.con == con)
					{
						threadRecv->taskQue.Post(itr->first);
						break;
					}
				}
				break;
			}
			case wxSOCKET_LOST:
			{
				for (userList::iterator itr = users.begin(), itrEnd = users.end(); itr != itrEnd; itr++)
				{
					if (itr->second.con == con)
					{
						onDelID = itr->second.uID;
						wxIPV4address localAddr;
						con->GetLocal(localAddr);
						freePort(localAddr.Service());
						con->Destroy();
						int i = 0;
						std::list<int>::iterator itr2;
						for (itr2 = userIDs.begin(); *itr2 != itr->second.uID; itr2++)i++;
						if (listUser->GetSelection() == i)
							textMsg->SetValue(wxEmptyString);
						listUser->Delete(i);
						userIDs.erase(itr2);
						users.erase(itr);
						break;
					}
				}
				break;
			}
		}
	}
	catch (std::exception ex)
	{
		textInfo->AppendText(ex.what() + std::string("\n"));
	}
}

void mainFrame::thread_Message(wxThreadEvent& event)
{
	int uID = event.GetInt();
	if (uID == -1)
		textInfo->AppendText(event.GetString());
	else
	{
		user &usr = users[uID];
		wxString msg = event.GetString();
		usr.log.append(msg);
		if (listUser->GetSelection() != -1)
		{
			std::list<int>::iterator itr2 = userIDs.begin();
			for (int i = listUser->GetSelection(); i > 0; itr2++)i--;
			if (uID == *itr2)
				textMsg->AppendText(msg);
			else
				textInfo->AppendText("Received message from " + usr.addr.IPAddress() + "\n");
		}
		else
			textInfo->AppendText("Received message from " + usr.addr.IPAddress() + "\n");
	}
}

void mainFrame::mainFrame_Close(wxCloseEvent& event)
{
	try
	{
		threadPing->Delete();
		threadMsgSend->Delete();
		threadFileSend->Delete();
		threadRecv->Delete();
		for (userList::iterator itr = users.begin(), itrEnd = users.end(); itr != itrEnd; itr++)
		{
			onDelID = itr->second.uID;
			user &usr = itr->second;
			wxIPV4address localAddr;
			usr.con->GetLocal(localAddr);
			freePort(localAddr.Service());
			usr.con->Destroy();
		}
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
		for (int i = 5001; i <= 10000; i++)
			ports.push_back(i);
		std::srand(std::time(NULL));
		e0str = getPublicKey();
		unsigned short e0len = wxUINT16_SWAP_ON_BE(static_cast<unsigned short>(e0str.size()));
		e0str = std::string(reinterpret_cast<const char*>(&e0len), sizeof(unsigned short) / sizeof(char)) + e0str;
		form = new mainFrame(wxT("Messenger"));
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
	return 0;
}
