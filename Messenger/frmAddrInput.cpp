#include "stdafx.h"
#include "frmAddrInput.h"

frmAddrInput::frmAddrInput(const wxString& title, int default_port)
	: wxDialog(NULL, ID_FRAME, title, wxDefaultPosition, wxSize(294, 118))
{
	Center();

	panel = new wxPanel(this);
	wxStaticText *label;

	label = new wxStaticText(panel, wxID_ANY,
		wxT("Address"),
		wxPoint(12, 12),
		wxSize(51, 21)
		);
	textAddr = new wxTextCtrl(panel, ID_TEXTADDR,
		wxEmptyString,
		wxPoint(69, 12),
		wxSize(104, 21)
		);
	label = new wxStaticText(panel, wxID_ANY,
		wxT("Port"),
		wxPoint(179, 12),
		wxSize(33, 21)
		);
	textPort = new wxTextCtrl(panel, ID_TEXTPORT,
		std::to_string(default_port),
		wxPoint(218, 12),
		wxSize(48, 21)
		);
	buttonOK = new wxButton(panel, wxID_OK,
		wxT("OK"),
		wxPoint(64, 42),
		wxSize(72, 30)
		);
	buttonCancel = new wxButton(panel, wxID_CANCEL,
		wxT("Cancel"),
		wxPoint(142, 42),
		wxSize(72, 30)
		);
}

bool frmAddrInput::CheckInput()
{
	if (textAddr->GetValue().empty())
		return false;
	try
	{
		int port = std::stoi(textPort->GetValue().ToStdWstring());
		if (port > 0 && port < UINT16_MAX)
			return false;
	}
	catch (std::out_of_range &)
	{
		return false;
	}
	catch (std::invalid_argument &)
	{
		return false;
	}
	return true;
}
