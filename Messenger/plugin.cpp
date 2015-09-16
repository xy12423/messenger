#include "stdafx.h"
#include "global.h"
#include "plugin.h"

struct regRecord
{
	regRecord() { used = false; callback = nullptr; }
	regRecord(cbOnDataPtr _callback) { used = true; callback = _callback; }
	bool used;
	cbOnDataPtr callback;
} regRecords[256];
std::unordered_set<std::shared_ptr<wxDynamicLibrary>> plugins;

const wchar_t* RegNextTypeFuncName = wxT("RegNextType");
const wchar_t* SetSendDataHandlerFuncName = wxT("SetSendDataHandler");
const wchar_t* cbOnDataFuncName = wxT("OnData");

extern void plugin_SendDataHandler(int to, const char* data, size_t size);

bool load_plugin(const std::wstring &plugin_full_path)
{
	std::shared_ptr<wxDynamicLibrary> plugin = std::make_shared<wxDynamicLibrary>(plugin_full_path);
	if (!plugin->IsLoaded())
		return false;	//Plugin not loaded
	plugins.emplace(plugin);

	RegNextTypePtr reg = reinterpret_cast<RegNextTypePtr>(plugin->GetSymbol(RegNextTypeFuncName));
	if (reg == nullptr)
		return false;	//RegNextType not found
	SetSendDataHandlerPtr setH = reinterpret_cast<SetSendDataHandlerPtr>(plugin->GetSymbol(SetSendDataHandlerFuncName));
	if (setH == nullptr)
		return false;	//cbOnData not found
	cbOnDataPtr callback = reinterpret_cast<cbOnDataPtr>(plugin->GetSymbol(cbOnDataFuncName));
	if (callback == nullptr)
		return false;	//cbOnData not found

	uint8_t nextReg = reg();
	while (nextReg & 0x80)
	{
		if (regRecords[nextReg].used)
			return false;	//Confliction

		regRecords[nextReg].used = true;
		regRecords[nextReg].callback = callback;

		nextReg = reg();
	}
	setH(plugin_SendDataHandler);

	std::cout << "Plugin loaded:" << wxConvLocal.cWC2MB(plugin_full_path.c_str()) << std::endl;
	return true;
}

void plugin_on_data(int from, uint8_t type, const char* data, const char* dataEnd)
{
	if (regRecords[type].used)
		(*regRecords[type].callback)(from, type, data, dataEnd);
}
