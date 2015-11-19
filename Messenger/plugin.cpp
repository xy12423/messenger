#include "stdafx.h"
#include "plugin.h"

typedef void(*RegPluginPtr)(plugin_id_type plugin_id);
typedef uint8_t(*RegNextTypePtr)();
typedef const char*(*RegNextMethodPtr)();

typedef void*(*GetMethodHandlerPtr)(const char* method_name);
typedef void(*SetGetMethodHandlerPtr)(GetMethodHandlerPtr handler);
typedef void(*SetHandlerPtr)(void* handler);

typedef void(*OnDataPtr)(int from, uint8_t type, const char* data, uint32_t length);

struct TypeReg
{
	bool used = false;
	OnDataPtr callback = nullptr;
	uint8_t redirect;
	plugin_id_type plugin_id;
} TypeRegs[0x80];
std::list<plugin_id_type> free_plugin_id;

typedef std::unique_ptr<wxDynamicLibrary> lib_ptr;

enum ExportFunc {
	RegPlugin,
	RegNextType,
	RegNextMethod,
	SetGetMethodHandler,
	OnData,

	ExportFuncCount
};
std::wstring ExportFuncName[ExportFuncCount] = {
	wxT("RegPlugin"),
	wxT("RegNextType"),
	wxT("RegNextMethod"),
	wxT("SetGetMethodHandler"),
	wxT("OnData")
};

const int ExportHandlerCount = ExportHandlerID::ExportHandlerCount;
std::wstring ExportHandlerName[ExportHandlerCount] = {
	wxT("SendDataHandler"),
	wxT("ConnectToHandler"),
	wxT("NewUserHandler"),
	wxT("DelUserHandler"),
	wxT("UserMsgHandler"),
};
void *ExportHandlers[ExportHandlerCount];

std::unordered_set<lib_ptr> plugins;
std::unordered_map<std::string, void*> plugin_methods;

void* plugin_GetMethodHandler(const char* method_name)
{
	std::unordered_map<std::string, void*>::iterator itr = plugin_methods.find(method_name);
	if (itr != plugin_methods.end())
		return itr->second;
	return nullptr;
}

bool new_plugin_id(std::list<plugin_id_type>::iterator &ret)
{
	if (free_plugin_id.empty())
		return false;
	ret = free_plugin_id.begin();
	for (int i = std::rand() % free_plugin_id.size(); i > 0; i--)
		ret++;
	return true;
}

void plugin_init()
{
	for (int i = 0; i <= (RAND_MAX < 0xFFF ? RAND_MAX : 0xFFF); i++)
		free_plugin_id.push_back(i);
}

void set_method(const std::string& method, void* method_ptr)
{
	if (method_ptr == nullptr)
		return;
	if (plugin_methods.find(method) != plugin_methods.end())
		return;
	plugin_methods.emplace(method, method_ptr);
}

void set_handler(unsigned int id, void* handler)
{
	if (id < ExportHandlerCount)
		ExportHandlers[id] = handler;
}

int load_plugin(const std::wstring &plugin_full_path)
{
	std::list<plugin_id_type>::iterator plugin_id_itr;
	plugin_id_type plugin_id;
	try
	{
		lib_ptr plugin = std::make_unique<wxDynamicLibrary>(plugin_full_path);
		if (!plugin->IsLoaded())
			throw(-1);	//Plugin not loaded

		//Load basic symbols
		void *ExportFuncPtr[ExportFuncCount];
		for (int i = 0; i < ExportFuncCount; i++)
		{
			ExportFuncPtr[i] = plugin->GetSymbol(ExportFuncName[i]);
			if (ExportFuncPtr[i] == nullptr)
				throw(-1);	//Symbol not found
		}
		RegNextTypePtr regType = reinterpret_cast<RegNextTypePtr>(ExportFuncPtr[RegNextType]);
		RegNextMethodPtr regMethod = reinterpret_cast<RegNextMethodPtr>(ExportFuncPtr[RegNextMethod]);
		OnDataPtr callback = reinterpret_cast<OnDataPtr>(ExportFuncPtr[OnData]);

		//Alloc new plugin id
		if (!new_plugin_id(plugin_id_itr))
			throw(-1);	//No more plugin id
		plugin_id = *plugin_id_itr;
		reinterpret_cast<RegPluginPtr>(ExportFuncPtr[RegPlugin])(plugin_id);
		reinterpret_cast<SetGetMethodHandlerPtr>(ExportFuncPtr[SetGetMethodHandler])(plugin_GetMethodHandler);

		//Get methods
		std::unordered_map<std::string, void*> methods;
		std::unordered_map<std::string, void*>::iterator itrEnd = plugin_methods.end();
		const char* nextMethodCStr = regMethod();
		std::string nextMethod;
		while (nextMethodCStr != nullptr && !(nextMethod.assign(nextMethodCStr)).empty())
		{
			if (plugin_methods.find(nextMethod) != itrEnd)
				throw(-1);	//Confliction

			void* nextMethodPtr = plugin->GetSymbol(nextMethod);
			if (nextMethodPtr == nullptr)
				throw(-1);	//Method not found

			methods.emplace(nextMethod, nextMethodPtr);
			nextMethodCStr = regMethod();
		}

		//Get types
		std::unordered_set<uint8_t> types;
		uint8_t nextType = regType();
		while (nextType & 0x80)
		{
			nextType &= 0x7F;
			if (TypeRegs[nextType].used)
				throw(-1);	//Confliction
			types.emplace(nextType);
			nextType = regType();
		}

		//Set handlers
		for (int i = 0; i < ExportHandlerCount; i++)
		{
			SetHandlerPtr SetHandler = reinterpret_cast<SetHandlerPtr>(plugin->GetSymbol(wxT("Set") + ExportHandlerName[i]));
			if (SetHandler == nullptr)
				throw(-1);	//Symbol not found
			SetHandler(ExportHandlers[i]);
		}

		//Reg methods and types
		for (const std::pair<std::string, void*> &method : methods)
			plugin_methods.emplace(method);
		for (uint8_t type : types)
		{
			TypeRegs[type].used = true;
			TypeRegs[type].callback = callback;
			TypeRegs[type].redirect = type | 0x80;
			TypeRegs[type].plugin_id = plugin_id;
		}

		plugins.emplace(std::move(plugin));

		std::cout << "Plugin loaded:" << wxConvLocal.cWC2MB(plugin_full_path.c_str()) << std::endl;
	}
	catch (std::exception &ex)
	{
		std::cerr << ex.what() << std::endl;
		return -1;
	}
	catch (int) { return -1; }
	
	free_plugin_id.erase(plugin_id_itr);
	return plugin_id;
}

bool plugin_check_id_type(uint16_t plugin_id, uint8_t type)
{
	return (type & 0x80) && (TypeRegs[type & 0x7F].plugin_id == plugin_id);
}

void plugin_on_data(int from, uint8_t type, const char* data, uint32_t len)
{
	if ((type & 0x80) != 0)
	{
		type &= 0x7F;
		if (TypeRegs[type].used)
			TypeRegs[type].callback(from, TypeRegs[type].redirect, data, len);
	}
}
