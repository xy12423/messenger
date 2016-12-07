#include "stdafx.h"
#include "session.h"
#include "plugin.h"
#include "main.h"

extern FileSendThread *threadFileSend;
extern std::unordered_map<user_id_type, user_ext_type> user_ext;
const char* IMG_TMP_PATH_NAME = ".messenger_tmp";
const char* IMG_TMP_FILE_NAME = ".messenger_tmp_";

const char* privatekeyFile = ".privatekey";
const char* publickeysFile = ".publickey";

struct data_view
{
	data_view(const char* _data, size_t _size)
		:data(_data), size(_size)
	{}
	data_view(const std::string &_data)
		:data(_data.data()), size(_data.size())
	{}

	template <typename _Ty>
	inline void read(_Ty &ret) {
		if (size < sizeof(_Ty))
			throw(wx_srv_interface_error());
		size -= sizeof(_Ty);
		ret = boost::endian::little_to_native(*reinterpret_cast<const _Ty*>(data));
		data += sizeof(_Ty);
	}
	inline void read(char* dst, size_t _size) { if (size < _size) throw(wx_srv_interface_error()); memcpy(dst, data, _size); data += _size; size -= _size; }
	inline void read(std::string& dst, size_t _size) { if (size < _size) throw(wx_srv_interface_error()); dst.append(data, _size); data += _size; size -= _size; }
	inline void check(size_t count) { if (size < count) throw(wx_srv_interface_error()); }
	inline void skip(size_t count) { if (size < count) throw(wx_srv_interface_error()); data += count; size -= count; }

	const char* data;
	size_t size;
};

wx_srv_interface::wx_srv_interface(asio::io_service& _main_io_service,
	asio::io_service& _misc_io_service,
	asio::ip::tcp::endpoint _local_endpoint,
	crypto::server& _crypto_srv)
	:msgr_proto::server(_main_io_service, _misc_io_service, _local_endpoint, _crypto_srv)
{
	if (fs::exists(publickeysFile))
	{
		std::ifstream fin(publickeysFile, std::ios_base::in | std::ios_base::binary);
		std::vector<char> buf_key, buf_ex;
		char size_buf[sizeof(uint16_t)];
		fin.read(size_buf, sizeof(uint16_t));
		while (!fin.eof())
		{
			//read key
			buf_key.resize(static_cast<uint16_t>(size_buf[0]) | (size_buf[1] << 8));
			fin.read(buf_key.data(), buf_key.size());
			if (fin.eof())
				break;
			//read extra data
			fin.read(size_buf, sizeof(uint16_t));
			buf_ex.resize(static_cast<uint16_t>(size_buf[0]) | (size_buf[1] << 8));
			fin.read(buf_ex.data(), buf_ex.size());
			if (fin.eof())
				break;
			//emplace
			certifiedKeys.emplace(std::string(buf_key.data(), buf_key.size()), std::string(buf_ex.data(), buf_ex.size()));
			//read next size
			fin.read(size_buf, sizeof(uint16_t));
		}

		fin.close();
	}
}

wx_srv_interface::~wx_srv_interface()
{
	std::ofstream fout(publickeysFile, std::ios_base::out | std::ios_base::binary);

	auto itr = certifiedKeys.begin(), itrEnd = certifiedKeys.end();
	for (; itr != itrEnd; itr++)
	{
		const std::string &key = itr->first, &ex = itr->second;
		fout.put(static_cast<char>(key.size()));
		fout.put(static_cast<char>(key.size() >> 8));
		fout.write(key.data(), key.size());
		fout.put(static_cast<char>(ex.size()));
		fout.put(static_cast<char>(ex.size() >> 8));
		fout.write(ex.data(), ex.size());
	}

	fout.close();
}

void wx_srv_interface::on_data(user_id_type id, const std::string& _data)
{
	try
	{
		data_view data(_data.data(), _data.size());
		user_ext_type &usr = user_ext.at(id);

		byte type;
		data.read(type);
		switch (type)
		{
			case PAC_TYPE_MSG:
			{
				if (frm == nullptr)
					throw(wx_srv_interface_error());

				data_size_type msg_size;
				data.read(msg_size);
				std::string msg_utf8;
				data.read(msg_utf8, msg_size);

				wxString msg(usr.addr + ':' + wxConvUTF8.cMB2WC(msg_utf8.c_str()) + '\n');

				wxThreadEvent *newEvent = new wxThreadEvent;
				newEvent->SetPayload<gui_callback>([this, id, msg]() {
					user_ext_type &usr = user_ext.at(id);
					usr.log.push_back(msg);
					if (frm->listUser->GetSelection() != -1)
					{
						if (id == frm->userIDs[frm->listUser->GetSelection()])
						{
							frm->textMsg->AppendText(msg);
							frm->textMsg->ShowPosition(frm->textMsg->GetLastPosition());
						}
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
			case PAC_TYPE_FILE_H:
			{
				data_size_type blockCountAll, fNameLen;
				data.read(blockCountAll);
				data.read(fNameLen);

				std::wstring fName;
				{
					size_t tmp;
					data.check(fNameLen);
					wxWCharBuffer wbuf = wxConvUTF8.cMB2WC(data.data, fNameLen, &tmp);
					data.skip(fNameLen);
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
			case PAC_TYPE_FILE_B:
			{
				data_size_type dataSize;
				data.read(dataSize);

				data.check(dataSize);

				if (usr.blockLast > 0)
				{
					std::ofstream fout(usr.recvFile, std::ios::out | std::ios::binary | std::ios::app);
					fout.write(data.data, dataSize);
					data.skip(dataSize);
					fout.close();
					usr.blockLast--;

					std::cout << usr.recvFile << ":" << usr.blockLast << " block(s) last" << std::endl;

					if (usr.blockLast == 0)
						usr.recvFile.clear();
				}

				break;
			}
			case PAC_TYPE_IMAGE:
			{
				if (frm == nullptr)
					throw(wx_srv_interface_error());

				data_size_type image_size;
				data.read(image_size);

				int next_image_id;
				new_image_id(next_image_id);
				fs::path image_path = IMG_TMP_PATH_NAME;
				image_path /= std::to_string(id);
				image_path /= ".messenger_tmp_" + std::to_string(next_image_id);

				data.check(image_size);
				std::ofstream fout(image_path.string(), std::ios_base::out | std::ios_base::binary);
				fout.write(data.data, image_size);
				fout.close();
				data.skip(image_size);

				wxImage image(image_path.native(), wxBITMAP_TYPE_ANY);
				if (image.IsOk())
				{
					wxThreadEvent *newEvent = new wxThreadEvent;
					newEvent->SetPayload<gui_callback>([this, id, image_path]() {
						user_ext_type &usr = user_ext.at(id);
						usr.log.push_back(usr.addr + ":\n");
						usr.log.push_back(image_path);
						usr.log.push_back("\n");

						if (frm->listUser->GetSelection() != -1)
						{
							if (id == frm->userIDs[frm->listUser->GetSelection()])
							{
								frm->textMsg->AppendText(usr.addr + ":\n");
								frm->textMsg->WriteImage(image_path.native(), wxBITMAP_TYPE_ANY);
								frm->textMsg->AppendText("\n");
								frm->textMsg->ShowPosition(frm->textMsg->GetLastPosition());
							}
							else
								frm->textInfo->AppendText("Received message from " + usr.addr + "\n");
						}
						else
							frm->textInfo->AppendText("Received message from " + usr.addr + "\n");

						if (!frm->IsActive())
							frm->RequestUserAttention();
					});
					wxQueueEvent(frm, newEvent);
				}

				break;
			}
			default:
			{
				if ((type & 0x80) != 0)
					plugin_on_data(id, type, data.data, data.size);
				break;
			}
		}
	}
	catch (wx_srv_interface_error &) {}
	catch (std::exception &ex)
	{
		std::cerr << ex.what() << std::endl;
	}
	catch (...)
	{
		throw;
	}
}

void wx_srv_interface::on_join(user_id_type id, const std::string& key)
{
	if (frm == nullptr)
		return;

	user_ext_type &ext = user_ext.emplace(id, user_ext_type()).first->second;
	ext.addr = wxConvLocal.cMB2WC(get_session(id)->get_address().c_str());

	fs::path tmp_path = IMG_TMP_PATH_NAME;
	tmp_path /= std::to_string(id);
	fs::create_directories(tmp_path);

	wxThreadEvent *newEvent = new wxThreadEvent;
	newEvent->SetPayload<gui_callback>([this, id, key]() {
		user_ext_type &ext = user_ext.at(id);
		std::wstring &addr = ext.addr;

		frm->listUser->Append(ext.addr);
		if (frm->listUser->GetSelection() == -1)
			frm->listUser->SetSelection(frm->listUser->GetCount() - 1);
		frm->userIDs.push_back(id);

		auto itr = certifiedKeys.end();
		if (!key.empty())
		{
			itr = certifiedKeys.find(key);
			if (itr == certifiedKeys.end())
			{
				int answer = wxMessageBox(wxT("The public key from ") + addr + wxT(" hasn't shown before.Trust it?"), wxT("Confirm"), wxYES_NO | wxCANCEL);
				if (answer == wxNO)
					disconnect(id);
				else
				{
					if (answer == wxYES)
					{
						wxTextEntryDialog dlg(frm, "Set a comment for this key!", "Set comment");
						if (dlg.ShowModal() != wxID_OK)
							dlg.SetValue(wxEmptyString);
						certify_key(key, std::string(dlg.GetValue().utf8_str()));
					}
					itr = certifiedKeys.find(key);
				}
			}
		}

		if (itr != certifiedKeys.end())
		{
			wxString new_label = ext.addr;
			new_label.Append('(');
			new_label.Append(wxConvUTF8.cMB2WC(itr->second.data()));
			new_label.Append(')');
			frm->listUser->SetString(frm->listUser->GetCount() - 1, new_label);
		}
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
		std::vector<user_id_type>::iterator itr = frm->userIDs.begin(), itrEnd = frm->userIDs.end();
		for (; itr != itrEnd && *itr != id; itr++)i++;
		if (frm->listUser->GetSelection() == i)
			frm->textMsg->SetValue(wxEmptyString);
		frm->listUser->Delete(i);
		frm->userIDs.erase(itr);
		user_ext.erase(id);

		fs::path tmp_path = IMG_TMP_PATH_NAME;
		tmp_path /= std::to_string(id);
		fs::remove_all(tmp_path);
	});
	wxQueueEvent(frm, newEvent);
}

bool wx_srv_interface::new_rand_port(port_type& ret)
{
	if (static_port != -1)
		ret = static_cast<port_type>(static_port);
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
