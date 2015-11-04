#include "stdafx.h"
#include "crypto.h"
#include "session.h"
#include "threads.h"
#include "plugin.h"
#include "main.h"
#include "frmAddrInput.h"

const port_type portListener = 4826;
const char* plugin_file_name = "plugins.txt";

wxBEGIN_EVENT_TABLE(mainFrame, wxFrame)

EVT_LISTBOX(ID_LISTUSER, mainFrame::listUser_SelectedIndexChanged)

EVT_BUTTON(ID_BUTTONADD, mainFrame::buttonAdd_Click)
EVT_BUTTON(ID_BUTTONDEL, mainFrame::buttonDel_Click)

EVT_BUTTON(ID_BUTTONSEND, mainFrame::buttonSend_Click)
EVT_BUTTON(ID_BUTTONSENDFILE, mainFrame::buttonSendFile_Click)
EVT_BUTTON(ID_BUTTONCANCELSEND, mainFrame::buttonCancelSend_Click)
EVT_BUTTON(ID_BUTTONIMPORTKEY, mainFrame::buttonImportKey_Click)
EVT_BUTTON(ID_BUTTONEXPORTKEY, mainFrame::buttonExportKey_Click)

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

fileSendThread *threadFileSend;

server* srv;
std::unordered_map<user_id_type, user_ext_data> user_ext;
wx_srv_interface inter;
net::io_service main_io_service, misc_io_service;
iosrvThread *threadNetwork, *threadMisc;

void plugin_SendDataHandler(int to, const char* data, size_t size)
{
	std::string data_str(data, size);
	if (to == -1)
	{
		std::for_each(user_ext.begin(), user_ext.end(), [&data_str](const std::pair<user_id_type, user_ext_data> &p) {
			user_id_type id = p.first;
			misc_io_service.post([id, data_str]() {
				srv->send_data(id, data_str, session::priority_plugin);
			});
		});
	}
	else
	{
		misc_io_service.post([to, data_str]() {
			srv->send_data(to, data_str, session::priority_plugin);
		});
	}
}

void plugin_ConnectToHandler(uint32_t addr, uint16_t port)
{
	srv->connect(addr, port);
}

std::string uid_global;
const char* plugin_api_GetUserID()
{
	return uid_global.c_str();
}

void plugin_api_Print(const char* msg)
{
	std::cout << "Plugin:" << msg << std::endl;
}

mainFrame::mainFrame(const wxString &title)
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
		wxSize(412, 42),
		wxTE_MULTILINE
		);
	buttonSend = new wxButton(panel, ID_BUTTONSEND,
		wxT("Send"),
		wxPoint(180, 369),
		wxSize(77, 42)
		);
	buttonSendFile = new wxButton(panel, ID_BUTTONSENDFILE,
		wxT("Send File"),
		wxPoint(263, 369),
		wxSize(78, 42)
		);
	buttonCancelSend = new wxButton(panel, ID_BUTTONCANCELSEND,
		wxT("Cancel"),
		wxPoint(347, 369),
		wxSize(78, 42)
		);
	buttonImportKey = new wxButton(panel, ID_BUTTONIMPORTKEY,
		wxT("Import key"),
		wxPoint(431, 369),
		wxSize(78, 42)
		);
	buttonExportKey = new wxButton(panel, ID_BUTTONEXPORTKEY,
		wxT("Export key"),
		wxPoint(515, 369),
		wxSize(77, 42)
		);

	textInfo = new wxTextCtrl(panel, ID_TEXTINFO,
		wxEmptyString,
		wxPoint(12, 417),
		wxSize(580, 92),
		wxTE_MULTILINE | wxTE_READONLY
		);

	const int entry_count = 1;
	wxAcceleratorEntry entries[entry_count];
	entries[0].Set(wxACCEL_CTRL, WXK_RETURN, ID_BUTTONSEND);
	wxAcceleratorTable accel(entry_count, entries);
	SetAcceleratorTable(accel);

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

	if (fs::exists(plugin_file_name))
	{
		uid_global.assign(getUserIDGlobal());
		set_method("GetUserID", reinterpret_cast<void*>(plugin_api_GetUserID));
		set_method("Print", reinterpret_cast<void*>(plugin_api_Print));

		std::ifstream fin(plugin_file_name);
		std::string plugin_name_utf8;
		while (!fin.eof())
		{
			std::getline(fin, plugin_name_utf8);
			if (!plugin_name_utf8.empty())
			{
				std::wstring plugin_name(wxConvUTF8.cMB2WC(plugin_name_utf8.c_str()));
				load_plugin(plugin_name);
			}
		}
	}
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
		frmAddrInput inputDlg(wxT("Please input address"), portListener);
		if (inputDlg.ShowModal() != wxID_OK || inputDlg.CheckInput() == false)
			return;
		srv->connect(inputDlg.GetAddress().ToStdString(), inputDlg.GetPort());
	}
	catch (std::exception &ex)
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
			msgutf8.insert(0, 1, pac_type_msg);
			misc_io_service.post([uID, msgutf8]() {
				srv->send_data(uID, msgutf8, session::priority_msg);
			});
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
			threadFileSend->start(uID, fs::path(path));
		}
	}
}

void mainFrame::buttonCancelSend_Click(wxCommandEvent& event)
{
	if (listUser->GetSelection() != -1)
	{
		std::list<int>::iterator itr = userIDs.begin();
		for (int i = listUser->GetSelection(); i > 0; itr++)i--;
		int uID = *itr;
		threadFileSend->stop(uID);
		srv->get_session(uID)->stop_file_transfer();
	}
}

void mainFrame::buttonImportKey_Click(wxCommandEvent& event)
{
	wxFileDialog fileDlg(this);
	fileDlg.ShowModal();
	std::string path = fileDlg.GetPath().ToStdString();
	if ((!path.empty()) && fs::exists(path))
	{
		size_t pubCount = 0, keyLen = 0;
		std::ifstream publicIn(path, std::ios_base::in | std::ios_base::binary);
		publicIn.read(reinterpret_cast<char*>(&pubCount), sizeof(size_t));
		for (; pubCount > 0; pubCount--)
		{
			publicIn.read(reinterpret_cast<char*>(&keyLen), sizeof(size_t));
			char *buf = new char[keyLen];
			publicIn.read(buf, keyLen);
			srv->certify_key(std::string(buf, keyLen));
			delete[] buf;
		}
	}
}

void mainFrame::buttonExportKey_Click(wxCommandEvent& event)
{
	wxFileDialog fileDlg(this);
	fileDlg.ShowModal();
	std::string path = fileDlg.GetPath().ToStdString();
	if (!path.empty())
	{
		std::ofstream publicOut(path, std::ios_base::out | std::ios_base::binary);
		size_t pubCount = 1;
		publicOut.write(reinterpret_cast<char*>(&pubCount), sizeof(size_t));

		std::string key = getPublicKey();
		size_t keySize = key.size();
		publicOut.write(reinterpret_cast<char*>(&keySize), sizeof(size_t));
		publicOut.write(key.data(), keySize);

		publicOut.close();
	}
}

void mainFrame::thread_Message(wxThreadEvent& event)
{
	int id = event.GetInt();
	if (id == -1)
	{
		if (!IsActive())
			RequestUserAttention();
	}
	else
	{
		int answer = wxMessageBox(wxT("The public key from " + user_ext.at(id).addr + " hasn't shown before.Trust it?"), wxT("Confirm"), wxYES_NO);
		if (answer != wxYES)
			srv->disconnect(id);
		else
			srv->certify_key(event.GetPayload<std::string>());
	}
}

void mainFrame::mainFrame_Close(wxCloseEvent& event)
{
	try
	{
		std::cout.rdbuf(cout_orig);
		std::cerr.rdbuf(cerr_orig);
		delete textStrm;

		threadFileSend->stop_thread();
		threadFileSend->Delete();

		inter.set_frame(nullptr);
	}
	catch (std::exception &ex)
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
		threadMisc = new iosrvThread(misc_io_service);
		if (threadMisc->Run() != wxTHREAD_NO_ERROR)
		{
			delete threadMisc;
			throw(std::runtime_error("Can't create iosrvThread"));
		}
		
		for (int i = 5001; i <= 10000; i++)
			inter.free_rand_port(i);
		srv = new server(main_io_service, misc_io_service, &inter, net::ip::tcp::endpoint(net::ip::tcp::v4(), portListener));

		form = new mainFrame(wxT("Messenger"));
		form->Show();
		inter.set_frame(form);
	}
	catch (std::exception &ex)
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
		threadMisc->stop();
		threadMisc->Delete();

		threadNetwork->stop();
		threadNetwork->Delete();

		delete srv;
	}
	catch (...)
	{
		return 1;
	}

	return 0;
}
