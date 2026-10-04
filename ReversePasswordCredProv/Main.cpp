#include "ReversePasswordCredProv.hpp"

#pragma comment(lib, "Credui.lib")
#pragma comment(lib, "Netapi32.lib")
#pragma comment(lib, "Secur32.lib")

// exported symbols (in addition to DllMain)
#pragma comment(linker, "/export:DllCanUnloadNow,PRIVATE")
#pragma comment(linker, "/export:DllGetClassObject,PRIVATE")
#pragma comment(linker, "/export:DllRegisterServer,PRIVATE")
#pragma comment(linker, "/export:DllUnregisterServer,PRIVATE")


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
