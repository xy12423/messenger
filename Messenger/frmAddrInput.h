#pragma once

#ifndef _H_FRM_ADDRINPUT
#define _H_FRM_ADDRINPUT

class frmAddrInput : public wxDialog
{
public:
	frmAddrInput(const wxString& title, int default_port);

	wxString GetAddress() { return textAddr->GetValue(); }
	int GetPort() { return std::stoi(textPort->GetValue().ToStdWstring()); }

	bool CheckInput();

private:
	enum itemID {
		ID_FRAME = 100,
		ID_TEXTADDR, ID_TEXTPORT
	};

	wxPanel *panel;

	wxTextCtrl *textAddr, *textPort;
	wxButton *buttonOK, *buttonCancel;
};

#endif
