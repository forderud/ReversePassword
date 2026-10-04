#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#include <windows.h>
#include <atlbase.h>
#include <cassert>
#include <string>

#include "ReversePasswordEventProvider.h" // custom event provider

// exported symbols (in addition to DllMain)
#pragma comment(linker, "/export:DllRegisterServer,PRIVATE")
#pragma comment(linker, "/export:DllUnregisterServer,PRIVATE")


/** Return the full path for the current EXE or DLL. */
inline std::wstring GetModuleFolderPath() {
    HMODULE module = nullptr;
    // Get handle to exe/dll that this static lib is linked against
    auto* module_ptr = (wchar_t const*)GetModuleFolderPath; // pointer to current function
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, module_ptr, &module);

    // retrieve full exe/dll path (incl. filename)
    wchar_t file_path[MAX_PATH] = {};
    GetModuleFileNameW(module, file_path, static_cast<DWORD>(std::size(file_path)));
    return file_path;
}

/** DLL entry point (does nothing). */
BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved){
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


/** Adds entries to the system registry.
    DOC: https://learn.microsoft.com/en-us/windows/win32/eventlog/event-sources */
STDAPI DllRegisterServer() {
    CRegKey parent;
    LSTATUS res = parent.Open(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application", KEY_READ | KEY_WRITE);
    assert(res == ERROR_SUCCESS);
    if (res != ERROR_SUCCESS)
        return E_UNEXPECTED;

    CRegKey reg;
    res = reg.Create(parent, L"ReversePassword");
    assert(res == ERROR_SUCCESS);
    if (res != ERROR_SUCCESS)
        return E_UNEXPECTED;

    {
        // number of event categories supported
        res = reg.SetDWORDValue(L"CategoryCount", PROVIDER_CATEGORY_COUNT);
        assert(res == ERROR_SUCCESS);

        std::wstring dllPath = GetModuleFolderPath();

        // category message file with language-dependent category strings
        res = reg.SetStringValue(L"CategoryMessageFile", dllPath.c_str());
        assert(res == ERROR_SUCCESS);

        // event message file(s) with language-dependent event strings
        res = reg.SetStringValue(L"EventMessageFile", dllPath.c_str());
        assert(res == ERROR_SUCCESS);

        // parameter message file with language-independent strings to be inserted into event description strings
        res = reg.SetStringValue(L"ParameterMessageFile", dllPath.c_str());
        assert(res == ERROR_SUCCESS);

        DWORD flags = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE; // can also include EVENTLOG_AUDIT_SUCCESS & EVENTLOG_AUDIT_FAILURE
        res = reg.SetDWORDValue(L"TypesSupported", flags);
        assert(res == ERROR_SUCCESS);
    }

    return NOERROR;
}


/** Removes entries from the system registry. */
STDAPI DllUnregisterServer() {
    CRegKey parent;
    LSTATUS res = parent.Open(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application", KEY_READ | KEY_WRITE);
    assert(res == ERROR_SUCCESS);
    if (res != ERROR_SUCCESS)
        return E_UNEXPECTED;

    res = parent.DeleteSubKey(L"ReversePassword");
    assert(res == ERROR_SUCCESS);
    if (res != ERROR_SUCCESS)
        return E_UNEXPECTED;

    return NOERROR;
}
