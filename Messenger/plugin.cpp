#include "stdafx.h"
#include "plugin.h"

typedef void(*RegPluginPtr)(plugin_id_type plugin_id);
typedef uint8_t(*RegNextTypePtr)();
typedef const char*(*RegNextMethodPtr)();
typedef const char*(*RegNextCallbackPtr)();

typedef void*(*GetMethodHandlerPtr)(const char* method_name);
typedef void(*SetGetMethodHandlerPtr)(GetMethodHandlerPtr handler);
typedef void*(*GetCallbackHandlerPtr)(plugin_id_type id, const char* method_name);
typedef void(*SetGetCallbackHandlerPtr)(GetCallbackHandlerPtr handler);
typedef void(*SetHandlerPtr)(void* handler);

typedef void(*InitPtr)();

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
	RegNextCallback,

	SetGetMethodHandler,
	SetGetCallbackHandler,

	OnData,

	ExportFuncCount
};
std::wstring ExportFuncName[ExportFuncCount] = {
	wxT("RegPlugin"),
	wxT("RegNextType"),
	wxT("RegNextMethod"),
	wxT("RegNextCallback"),

	wxT("SetGetMethodHandler"),
	wxT("SetGetCallbackHandler"),

	wxT("OnData")
};

const int ExportHandlerCount = ExportHandlerID::ExportHandlerCount;
std::wstring ExportHandlerName[ExportHandlerCount] = {
	wxT("SendDataHandler"),
	wxT("ConnectToHandler"),
};
void *ExportHandlers[ExportHandlerCount];

typedef std::unordered_map<std::string, void*> plugin_methods_tp;
std::unordered_map<plugin_id_type, lib_ptr> plugins;
plugin_methods_tp plugin_methods;
std::unordered_map<plugin_id_type, plugin_methods_tp> plugin_callbacks;

void* get_method(const char* method_name)
{
	plugin_methods_tp::iterator itr = plugin_methods.find(method_name);
	if (itr != plugin_methods.end())
		return itr->second;
	return nullptr;
}

void* get_callback(plugin_id_type id, const char* callback_name)
{
	std::unordered_map<plugin_id_type, plugin_methods_tp>::iterator itr = plugin_callbacks.find(id);
	if (itr == plugin_callbacks.end())
		return nullptr;
	plugin_methods_tp::iterator itr2 = itr->second.find(callback_name);
	if (itr2 == itr->second.end())
		return nullptr;
	return itr2->second;
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
	for (plugin_id_type i = 0; i <= (RAND_MAX < 0xFFF ? RAND_MAX : 0xFFF); i++)
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
		RegNextCallbackPtr regCallback = reinterpret_cast<RegNextCallbackPtr>(ExportFuncPtr[RegNextCallback]);
		OnDataPtr cbOnData = reinterpret_cast<OnDataPtr>(ExportFuncPtr[OnData]);

		//Alloc new plugin id
		std::list<plugin_id_type>::iterator plugin_id_itr;
		if (!new_plugin_id(plugin_id_itr))
			throw(-1);	//No more plugin id
		plugin_id = *plugin_id_itr;
		reinterpret_cast<RegPluginPtr>(ExportFuncPtr[RegPlugin])(plugin_id);
		reinterpret_cast<SetGetMethodHandlerPtr>(ExportFuncPtr[SetGetMethodHandler])(get_method);
		reinterpret_cast<SetGetCallbackHandlerPtr>(ExportFuncPtr[SetGetCallbackHandler])(get_callback);

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

		//Get callbacks
		std::unordered_map<std::string, void*> callbacks;
		const char* nextCallbackCStr = regCallback();
		std::string nextCallback;
		while (nextCallbackCStr != nullptr && !(nextCallback.assign(nextCallbackCStr)).empty())
		{
			void* nextCallbackPtr = plugin->GetSymbol(nextCallback);
			if (nextCallbackPtr == nullptr)
				throw(-1);	//Callback not found

			callbacks.emplace(nextCallback, nextCallbackPtr);
			nextCallbackCStr = regCallback();
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

		//Reg methods, callbacks and types
		for (const std::pair<std::string, void*> &method : methods)
			plugin_methods.emplace(method);
		plugin_callbacks.emplace(plugin_id, std::move(callbacks));
		for (uint8_t type : types)
		{
			TypeRegs[type].used = true;
			TypeRegs[type].callback = cbOnData;
			TypeRegs[type].redirect = type | 0x80;
			TypeRegs[type].plugin_id = plugin_id;
		}

		lib_ptr &plugin_ref = plugins.emplace(plugin_id, std::move(plugin)).first->second;

		InitPtr Init = reinterpret_cast<InitPtr>(plugin_ref->GetSymbol(wxT("Init")));
		if (Init != nullptr)
		{
			try
			{
				Init();
			}
			catch (...) {}
		}

		std::cout << "Plugin loaded:" << wxConvLocal.cWC2MB(plugin_full_path.c_str()) << std::endl;

		free_plugin_id.erase(plugin_id_itr);
	}
	catch (std::exception &ex)
	{
		std::cerr << ex.what() << std::endl;
		return -1;
	}
	catch (int) { return -1; }
	
	return plugin_id;
}

bool plugin_check_id_type(plugin_id_type plugin_id, uint8_t type)
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
