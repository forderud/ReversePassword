#include "ReversePassword.hpp"

#pragma comment(lib, "Credui.lib")
#pragma comment(lib, "Netapi32.lib")
#pragma comment(lib, "Secur32.lib")

class ReversePasswordModule final : public CAtlDllModuleT<ReversePasswordModule> {
};

ReversePasswordModule g_module;


extern "C" BOOL WINAPI DllMain(HINSTANCE /*instance*/, DWORD reason, LPVOID reserved) {
    return g_module.DllMain(reason, reserved);
}

STDAPI DllCanUnloadNow() { return g_module.DllCanUnloadNow(); }
STDAPI DllGetClassObject(REFCLSID clsid, REFIID iid, LPVOID* object) { return g_module.DllGetClassObject(clsid, iid, object); }
STDAPI DllRegisterServer() { return g_module.DllRegisterServer(/*typelib*/false); }
STDAPI DllUnregisterServer() { return g_module.DllUnregisterServer(/*typelib*/false); }
