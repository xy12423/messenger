#include "stdafx.h"
#include "global.h"
#include "plugin.h"

typedef uint8_t(*RegNextTypePtr)();
typedef const char*(*RegNextMethodPtr)();

typedef void(*ConnectToHandlerPtr)(uint32_t addr);
typedef void(*SetConnectToHandlerPtr)(ConnectToHandlerPtr handler);

typedef void(*SendDataHandlerPtr)(int to, const char* data, size_t size);
typedef void(*SetSendDataHandlerPtr)(SendDataHandlerPtr handler);

typedef void*(*GetMethodHandlerPtr)(const char* method_name);
typedef void(*SetGetMethodHandlerPtr)(GetMethodHandlerPtr handler);

typedef void(*cbOnDataPtr)(int from, uint8_t type, const char* data, const char* dataEnd);

struct TypeReg
{
	bool used = false;
	cbOnDataPtr callback = nullptr;
	uint8_t redirect;
} TypeRegs[0x80];

typedef std::shared_ptr<wxDynamicLibrary> lib_ptr;

enum ExportFunc{
	RegNextType,
	RegNextMethod,
	SetConnectToHandler,
	SetSendDataHandler,
	SetGetMethodHandler,
	cbOnData,

	ExportFuncCount
};
std::wstring ExportFuncName[ExportFuncCount] = {
	wxT("RegNextType"),
	wxT("RegNextMethod"),
	wxT("SetConnectToHandler"),
	wxT("SetSendDataHandler"),
	wxT("SetGetMethodHandler"),
	wxT("OnData")
};

std::unordered_set<lib_ptr> plugins;
std::unordered_map<std::string, void*> plugin_methods;

void* plugin_GetMethodHandler(const char* method_name)
{
	std::unordered_map<std::string, void*>::iterator itr = plugin_methods.find(method_name);
	if (itr != plugin_methods.end())
		return itr->second;
	return nullptr;
}
extern void plugin_SendDataHandler(int to, const char* data, size_t size);
extern void plugin_ConnectToHandler(uint32_t addr);

bool load_plugin(const std::wstring &plugin_full_path)
{
	lib_ptr plugin = std::make_shared<wxDynamicLibrary>(plugin_full_path);
	if (!plugin->IsLoaded())
		return false;	//Plugin not loaded

	void *ExportFuncPtr[ExportFuncCount];
	for (int i = 0; i < ExportFuncCount; i++)
	{
		ExportFuncPtr[i] = plugin->GetSymbol(ExportFuncName[i]);
		if (ExportFuncPtr[i] == nullptr)
			return false;	//Symbol not found
	}
	RegNextTypePtr regType = reinterpret_cast<RegNextTypePtr>(ExportFuncPtr[RegNextType]);
	RegNextMethodPtr regMethod = reinterpret_cast<RegNextMethodPtr>(ExportFuncPtr[RegNextMethod]);
	cbOnDataPtr callback = reinterpret_cast<cbOnDataPtr>(ExportFuncPtr[cbOnData]);

	reinterpret_cast<SetGetMethodHandlerPtr>(ExportFuncPtr[SetGetMethodHandler])(plugin_GetMethodHandler);

	//Get methods
	std::unordered_map<std::string, void*> methods;
	std::unordered_map<std::string, void*>::iterator itrEnd = plugin_methods.end();
	const char* nextMethodCStr = regMethod();
	std::string nextMethod;
	while (nextMethodCStr != nullptr && !(nextMethod.assign(nextMethodCStr)).empty())
	{
		if (plugin_methods.find(nextMethod) != itrEnd)
			return false;	//Confliction

		void* nextMethodPtr = plugin->GetSymbol(nextMethod);
		if (nextMethodPtr == nullptr)
			return false;	//Method not found

		methods.emplace(nextMethod, nextMethodPtr);
		nextMethodCStr = regMethod();
	}

	//Get message types
	std::unordered_set<uint8_t> types;
	uint8_t nextType = regType();
	while (nextType & 0x80)
	{
		nextType &= 0x7F;
		if (TypeRegs[nextType].used)
			return false;	//Confliction
		types.emplace(nextType);
		nextType = regType();
	}

	std::for_each(methods.begin(), methods.end(), [](const std::pair<std::string, void*> &method) {
		plugin_methods.emplace(method);
	});
	std::for_each(types.begin(), types.end(), [callback](uint8_t type) {
		TypeRegs[type].used = true;
		TypeRegs[type].callback = callback;
		TypeRegs[type].redirect = type | 0x80;
	});

	reinterpret_cast<SetConnectToHandlerPtr>(ExportFuncPtr[SetConnectToHandler])(plugin_ConnectToHandler);
	reinterpret_cast<SetSendDataHandlerPtr>(ExportFuncPtr[SetSendDataHandler])(plugin_SendDataHandler);

	plugins.emplace(std::move(plugin));

	std::cout << "Plugin loaded:" << wxConvLocal.cWC2MB(plugin_full_path.c_str()) << std::endl;
	return true;
}

void plugin_on_data(int from, uint8_t type, const char* data, const char* dataEnd)
{
	if ((type & 0x80) != 0)
	{
		type &= 0x7F;
		if (TypeRegs[type].used)
			TypeRegs[type].callback(from, TypeRegs[type].redirect, data, dataEnd);
	}
}
