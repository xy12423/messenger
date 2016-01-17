#include "stdafx.h"
#include "crypto.h"
#include "session.h"
#include "threads.h"
#include "plugin.h"
#include "main.h"
#include "frmAddrInput.h"

const port_type portListenDefault = 4826;
port_type portListen = portListenDefault;
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
const int _GUI_SIZE_X = 620;
const int _GUI_SIZE_Y = 560;
#else
const int _GUI_SIZE_X = 600;
const int _GUI_SIZE_Y = 540;
#endif

fileSendThread *threadFileSend;
iosrvThread *threadNetwork, *threadMisc;

asio::io_service main_io_service, misc_io_service;
std::unique_ptr<msgr_proto::server> srv;
wx_srv_interface inter;

std::unordered_map<user_id_type, user_ext_type> user_ext;
std::unordered_map<plugin_id_type, plugin_info_type> plugin_info;
std::unordered_set<user_id_type> virtual_users;

void plugin_handler_SendData(plugin_id_type plugin_id, int to, const char* data, size_t size)
{
	if (!plugin_check_id_type(plugin_id, *data))
		return;
	std::string data_str(data, size);
	if (to == -1)
	{
		for (const std::pair<user_id_type, user_ext_type> &p : user_ext)
		{
			user_id_type id = p.first;
			misc_io_service.post([id, data_str]() {
				srv->send_data(id, data_str, msgr_proto::session::priority_plugin);
			});
		};
	}
	else
	{
		misc_io_service.post([to, data_str]() {
			srv->send_data(to, data_str, msgr_proto::session::priority_plugin);
		});
	}
}

void plugin_handler_ConnectTo(uint32_t addr, uint16_t port)
{
	srv->connect(addr, port);
}

int plugin_handler_NewVirtualUser(plugin_id_type plugin_id, const char* name)
{
	try
	{
		plugin_info_type &info = plugin_info.at(plugin_id);
		plugin_info_type::virtual_msg_handler_ptr virtual_msg_handler = info.virtual_msg_handler;
		std::string name_str = info.name;
		if (name[0] != '\0')
		{
			name_str.push_back(':');
			name_str.append(name);
		}

		std::shared_ptr<msgr_proto::virtual_session> new_session = std::make_shared<msgr_proto::virtual_session>(*srv, name_str);
		if (virtual_msg_handler == nullptr)
			new_session->set_callback([](const std::string &) {});
		else
		{
			new_session->set_callback([new_session, virtual_msg_handler](const std::string &data) {
				virtual_msg_handler(new_session->get_id(), data.data(), data.size());
			});
		}

		srv->join(new_session);
		new_session->start();
		user_id_type new_user_id = new_session->get_id();
		info.virtual_user_list.emplace(new_user_id);
		virtual_users.emplace(new_user_id);
		return new_user_id;
	}
	catch (...) {}
	return -1;
}

bool plugin_handler_DelVirtualUser(plugin_id_type plugin_id, uint16_t virtual_user_id)
{
	try
	{
		std::unordered_set<uint16_t> &virtual_user_list = plugin_info.at(plugin_id).virtual_user_list;
		std::unordered_set<uint16_t>::iterator itr = virtual_user_list.find(virtual_user_id);
		if (itr != virtual_user_list.end())
		{
			srv->leave(virtual_user_id);
			virtual_user_list.erase(itr);
			return true;
		}
	}
	catch (...) {}
	return false;
}

bool plugin_handler_VirtualUserMsg(plugin_id_type plugin_id, uint16_t virtual_user_id, const char* message, uint32_t length)
{
	try
	{
		plugin_info_type &info = plugin_info.at(plugin_id);
		if (info.virtual_user_list.find(virtual_user_id) != info.virtual_user_list.end())
		{
			std::dynamic_pointer_cast<msgr_proto::virtual_session>(srv->get_session(virtual_user_id))->push(std::string(message, length));
			return true;
		}
	}
	catch (...) {}
	return false;
}

std::string uid_global;
const char* plugin_method_GetUserID()
{
	return uid_global.c_str();
}

void plugin_method_Print(plugin_id_type plugin_id, const char* msg)
{
	try
	{
		plugin_info_type &info = plugin_info.at(plugin_id);
		std::cout << "Plugin:" << info.name << ':' << msg << std::endl;
	}
	catch (...) {}
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

	textStrm = new textStream(this, textInfo);
	cout_orig = std::cout.rdbuf();
	std::cout.rdbuf(textStrm);
	cerr_orig = std::cerr.rdbuf();
	std::cerr.rdbuf(textStrm);

	if (fs::exists(plugin_file_name))
	{
		plugin_init();
		uid_global.assign(getUserIDGlobal());
		set_method("GetUserID", reinterpret_cast<void*>(plugin_method_GetUserID));
		set_method("Print", reinterpret_cast<void*>(plugin_method_Print));

		set_handler(ExportHandlerID::SendDataHandler, reinterpret_cast<void*>(plugin_handler_SendData));
		set_handler(ExportHandlerID::ConnectToHandler, reinterpret_cast<void*>(plugin_handler_ConnectTo));

		set_method("NewUser", reinterpret_cast<void*>(plugin_handler_NewVirtualUser));
		set_method("DelUser", reinterpret_cast<void*>(plugin_handler_DelVirtualUser));
		set_method("UserMsg", reinterpret_cast<void*>(plugin_handler_VirtualUserMsg));

		std::ifstream fin(plugin_file_name);
		std::string plugin_path_utf8;
		while (!fin.eof())
		{
			std::getline(fin, plugin_path_utf8);
			if (!plugin_path_utf8.empty())
			{
				std::wstring plugin_path(wxConvUTF8.cMB2WC(plugin_path_utf8.c_str()));
				plugin_id_type plugin_id = load_plugin(plugin_path);
				plugin_info_type &info = plugin_info.emplace(plugin_id, plugin_info_type()).first->second;
				info.name = fs::path(plugin_path).filename().stem().string();
				info.plugin_id = plugin_id;
				info.virtual_msg_handler = reinterpret_cast<plugin_info_type::virtual_msg_handler_ptr>(get_callback(plugin_id, "OnUserMsg"));
			}
		}
	}
}

void mainFrame::listUser_SelectedIndexChanged(wxCommandEvent& event)
{
	int uID = userIDs[listUser->GetSelection()];
	textMsg->SetValue(user_ext[uID].log);
	textMsg->ShowPosition(user_ext[uID].log.size());
}

void mainFrame::buttonAdd_Click(wxCommandEvent& event)
{
	try
	{
		frmAddrInput inputDlg(wxT("Please input address"), portListen);
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
		if (virtual_users.find(userIDs[selection]) == virtual_users.end())
			srv->disconnect(userIDs[selection]);
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
			int uID = userIDs[listUser->GetSelection()];
			insLen(msgutf8);
			msgutf8.insert(0, 1, pac_type_msg);
			misc_io_service.post([uID, msgutf8]() {
				srv->send_data(uID, msgutf8, msgr_proto::session::priority_msg);
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
			int uID = userIDs[listUser->GetSelection()];
			threadFileSend->start(uID, fs::path(path));
		}
	}
}

void mainFrame::buttonCancelSend_Click(wxCommandEvent& event)
{
	if (listUser->GetSelection() != -1)
	{
		int uID = userIDs[listUser->GetSelection()];
		threadFileSend->stop(uID);
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
		std::vector<char> buf;

		for (; pubCount > 0; pubCount--)
		{
			publicIn.read(reinterpret_cast<char*>(&keyLen), sizeof(size_t));
			buf.resize(keyLen);
			publicIn.read(buf.data(), keyLen);
			srv->certify_key(std::string(buf.data(), keyLen));
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
	event.GetPayload<gui_callback>()();
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
	catch (std::exception &ex)
	{
		wxMessageBox(ex.what(), wxT("Error"), wxOK | wxICON_ERROR);
	}
	wxFrame::OnCloseWindow(event);
}

IMPLEMENT_APP(MyApp)

bool MyApp::OnInit()
{
	int stage = 0;
	try
	{
		port_type portsBegin = 5000, portsEnd = 9999;
		bool use_v6 = false;

		threadNetwork = new iosrvThread(main_io_service);
		stage = 1;
		threadMisc = new iosrvThread(misc_io_service);
		stage = 2;

		for (int i = 1; i < argc; i++)
		{
			std::string arg(argv[i]);
			if (arg.substr(0, 5) == "port=")
			{
				portListen = std::stoi(arg.substr(5));
			}
			else if (arg.substr(0, 6) == "ports=")
			{
				int pos = arg.find('-', 6);
				if (pos == std::string::npos)
				{
					inter.set_static_port(std::stoi(arg.substr(6)));
					portsBegin = 1;
					portsEnd = 0;
				}
				else
				{
					std::string ports_begin = arg.substr(6, pos - 6), ports_end = arg.substr(pos + 1);
					portsBegin = std::stoi(ports_begin);
					portsEnd = std::stoi(ports_end);
					inter.set_static_port(-1);
				}
			}
			else if (arg == "usev6")
			{
				use_v6 = true;
			}
			else
			{
				throw(std::invalid_argument("Invalid argument:" + arg));
			}
		}
		
		for (; portsBegin <= portsEnd; portsBegin++)
			inter.free_rand_port(portsBegin);
		srv = std::make_unique<msgr_proto::server>(main_io_service, misc_io_service, inter,
			asio::ip::tcp::endpoint((use_v6 ? asio::ip::tcp::v6() : asio::ip::tcp::v4()), portListen));

		threadFileSend = new fileSendThread(*srv);
		stage = 3;

		form = new mainFrame(wxT("Messenger"));
		form->Show();
		inter.set_frame(form);

		if (threadNetwork->Run() != wxTHREAD_NO_ERROR)
		{
			delete threadNetwork;
			throw(std::runtime_error("Can't run iosrvThread"));
		}
		if (threadMisc->Run() != wxTHREAD_NO_ERROR)
		{
			delete threadMisc;
			throw(std::runtime_error("Can't run iosrvThread"));
		}
		if (threadFileSend->Run() != wxTHREAD_NO_ERROR)
		{
			delete threadFileSend;
			throw(std::runtime_error("Can't run fileSendThread"));
		}
	}
	catch (std::exception &ex)
	{
		switch (stage)
		{
			case 3:
				threadFileSend->Delete();
			case 2:
				threadMisc->Delete();
			case 1:
				threadNetwork->Delete();
			default:
				break;
		}

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
		threadMisc->Delete();
		threadNetwork->Delete();

		srv.reset();
	}
	catch (...)
	{
		return 1;
	}

	return 0;
}
