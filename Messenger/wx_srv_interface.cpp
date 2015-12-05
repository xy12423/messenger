#include "stdafx.h"
#include "crypto.h"
#include "session.h"
#include "plugin.h"
#include "main.h"

extern fileSendThread *threadFileSend;
extern std::unordered_map<user_id_type, user_ext_type> user_ext;

#define checkErr(x) if (dataItr + (x) > dataEnd) throw(0)
#define read_uint(x)													\
	checkErr(sizeof_data_length);										\
	memcpy(reinterpret_cast<char*>(&(x)), dataItr, sizeof_data_length);	\
	dataItr += sizeof_data_length

void wx_srv_interface::on_data(user_id_type id, const std::string &data)
{
	try
	{
		const size_t sizeof_data_length = sizeof(data_length_type);
		const char *dataItr = data.data(), *dataEnd = data.data() + data.size();
		user_ext_type &usr = user_ext.at(id);

		byte type;
		checkErr(1);
		type = *dataItr;
		dataItr += 1;
		switch (type)
		{
			case pac_type_msg:
			{
				if (frm == nullptr)
					throw(0);

				data_length_type sizeMsg;
				read_uint(sizeMsg);

				checkErr(sizeMsg);
				std::string msg_utf8(dataItr, sizeMsg);
				dataItr += sizeMsg;

				wxString msg(usr.addr + ':' + wxConvUTF8.cMB2WC(msg_utf8.c_str()) + '\n');

				wxThreadEvent *newEvent = new wxThreadEvent;
				newEvent->SetPayload<gui_callback>([this, id, msg]() {
					user_ext_type &usr = user_ext.at(id);
					usr.log.append(msg);
					if (frm->listUser->GetSelection() != -1)
					{
						if (id == frm->userIDs[frm->listUser->GetSelection()])
							frm->textMsg->AppendText(msg);
						else
							frm->textInfo->AppendText("Received message from " + usr.addr + "\n");
					}
					else
						frm->textInfo->AppendText("Received message from " + usr.addr + "\n");

					if (!frm->IsActive())
						frm->RequestUserAttention();
				});
				wxQueueEvent(frm, newEvent);

				break;
			}
			case pac_type_file_h:
			{
				data_length_type recvLE;
				read_uint(recvLE);
				data_length_type blockCountAll = wxUINT32_SWAP_ON_BE(static_cast<data_length_type>(recvLE));

				read_uint(recvLE);
				data_length_type fNameLen = wxUINT32_SWAP_ON_BE(static_cast<data_length_type>(recvLE));

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
				usr.blockLast = blockCountAll;
				std::cout << "Receiving file " << fName << " from " << usr.addr << std::endl;

				break;
			}
			case pac_type_file_b:
			{
				data_length_type recvLE;
				read_uint(recvLE);
				data_length_type dataSize = wxUINT32_SWAP_ON_BE(static_cast<data_length_type>(recvLE));

				checkErr(dataSize);

				if (usr.blockLast > 0)
				{
					std::ofstream fout(usr.recvFile, std::ios::out | std::ios::binary | std::ios::app);
					fout.write(dataItr, dataSize);
					dataItr += dataSize;
					fout.close();
					usr.blockLast--;

					std::cout << usr.recvFile << ":" << usr.blockLast << " block(s) last" << std::endl;

					if (usr.blockLast == 0)
						usr.recvFile.clear();
				}

				break;
			}
			default:
			{
				if ((type & 0x80) != 0)
					plugin_on_data(id, type, dataItr, dataEnd - dataItr);
				break;
			}
		}
	}
	catch (std::exception &ex)
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

void wx_srv_interface::on_join(user_id_type id)
{
	if (frm == nullptr)
		return;

	wxThreadEvent *newEvent = new wxThreadEvent;
	newEvent->SetPayload<gui_callback>([this, id]() {
		user_ext_type &ext = user_ext.emplace(id, user_ext_type()).first->second;
		std::string addr = srv->get_session(id)->get_address();
		ext.addr = wxConvLocal.cMB2WC(addr.c_str());

		frm->listUser->Append(ext.addr);
		if (frm->listUser->GetSelection() == -1)
			frm->listUser->SetSelection(frm->listUser->GetCount() - 1);
		frm->userIDs.push_back(id);
	});
	wxQueueEvent(frm, newEvent);
}

void wx_srv_interface::on_leave(user_id_type id)
{
	if (frm == nullptr)
		return;

	threadFileSend->stop(id);
	wxThreadEvent *newEvent = new wxThreadEvent;
	newEvent->SetPayload<gui_callback>([this, id]() {
		int i = 0;
		std::vector<int>::iterator itr = frm->userIDs.begin(), itrEnd = frm->userIDs.end();
		for (; itr != itrEnd && *itr != id; itr++)i++;
		if (frm->listUser->GetSelection() == i)
			frm->textMsg->SetValue(wxEmptyString);
		frm->listUser->Delete(i);
		frm->userIDs.erase(itr);
		user_ext.erase(id);
	});
	wxQueueEvent(frm, newEvent);
}

void wx_srv_interface::on_unknown_key(user_id_type id, const std::string& key)
{
	if (frm == nullptr)
		return;

	wxThreadEvent *newEvent = new wxThreadEvent;
	newEvent->SetPayload<gui_callback>([this, id, key]() {
		int answer = wxMessageBox(wxT("The public key from " + user_ext.at(id).addr + " hasn't shown before.Trust it?"), wxT("Confirm"), wxYES_NO | wxCANCEL);
		if (answer == wxNO)
			srv->disconnect(id);
		else if (answer == wxYES)
			srv->certify_key(key);
	});
	wxQueueEvent(frm, newEvent);
}

bool wx_srv_interface::new_rand_port(port_type &ret)
{
	if (static_port != -1)
		ret = static_port;
	else
	{
		if (ports.empty())
			return false;
		std::list<port_type>::iterator portItr = ports.begin();
		for (int i = std::rand() % ports.size(); i > 0; i--)
			portItr++;
		ret = *portItr;
		ports.erase(portItr);
	}
	return true;
}

