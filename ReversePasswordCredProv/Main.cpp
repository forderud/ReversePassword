#include "CredentialProvider.hpp"

#include <array>

#pragma comment(lib, "Credui.lib")
#pragma comment(lib, "Netapi32.lib")
#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Shlwapi.lib")

// exported symbols (in addition to DllMain)
#pragma comment(linker, "/export:DllCanUnloadNow,PRIVATE")
#pragma comment(linker, "/export:DllGetClassObject,PRIVATE")
#pragma comment(linker, "/export:DllRegisterServer,PRIVATE")
#pragma comment(linker, "/export:DllUnregisterServer,PRIVATE")


HINSTANCE g_moduleInstance = nullptr;

namespace {
    constexpr WCHAR CredentialProviderName[] = L"ReversePassword Credential Provider";
    constexpr WCHAR RegistryName[] = L"ReversePasswordCredProv";

    HRESULT SetRegistryValue(HKEY key, const WCHAR* name, const WCHAR* value) {
        const DWORD size = static_cast<DWORD>((wcslen(value) + 1) * sizeof(WCHAR));
        const LSTATUS status = RegSetValueExW(key, name, 0, REG_SZ,
            reinterpret_cast<const BYTE*>(value), size);
        return status == ERROR_SUCCESS ? S_OK : HRESULT_FROM_WIN32(status);
    }

    HRESULT CreateRegistryKey(HKEY root, const std::wstring& path, const WCHAR* value, HKEY* key) {
        const LSTATUS status = RegCreateKeyExW(root, path.c_str(), 0, nullptr, 0,
            KEY_WRITE, nullptr, key, nullptr);
        if (status != ERROR_SUCCESS)
            return HRESULT_FROM_WIN32(status);

        if (!value)
            return S_OK;

        const HRESULT hr = SetRegistryValue(*key, nullptr, value);
        if (FAILED(hr))
            RegCloseKey(*key);
        return hr;
    }

    HRESULT RegisterServer() {
        std::array<WCHAR, 32768> modulePath{};
        const DWORD length = GetModuleFileNameW(g_moduleInstance, modulePath.data(),
            static_cast<DWORD>(modulePath.size()));
        if (!length)
            return HRESULT_FROM_WIN32(GetLastError());
        if (length == modulePath.size())
            return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);

        WCHAR clsid[39]{};
        if (!StringFromGUID2(CLSID_ReversePasswordCredProv, clsid, std::size(clsid)))
            return E_FAIL;

        const std::wstring clsidPath = std::wstring(L"CLSID\\") + clsid;
        HKEY key = nullptr;
        HRESULT hr = CreateRegistryKey(HKEY_CLASSES_ROOT, clsidPath, CredentialProviderName, &key);
        if (FAILED(hr))
            return hr;
        RegCloseKey(key);

        hr = CreateRegistryKey(HKEY_CLASSES_ROOT, clsidPath + L"\\InprocServer32", modulePath.data(), &key);
        if (FAILED(hr))
            return hr;
        hr = SetRegistryValue(key, L"ThreadingModel", L"Both");
        RegCloseKey(key);
        if (FAILED(hr))
            return hr;

        const std::wstring providerPath = std::wstring(
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\") + clsid;
        hr = CreateRegistryKey(HKEY_LOCAL_MACHINE, providerPath, RegistryName, &key);
        if (FAILED(hr))
            return hr;
        RegCloseKey(key);
        return S_OK;
    }

    HRESULT UnregisterServer() {
        WCHAR clsid[39]{};
        if (!StringFromGUID2(CLSID_ReversePasswordCredProv, clsid, std::size(clsid)))
            return E_FAIL;

        const std::wstring clsidPath = std::wstring(L"CLSID\\") + clsid;
        LSTATUS status = RegDeleteTreeW(HKEY_CLASSES_ROOT, clsidPath.c_str());
        if (status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND)
            return HRESULT_FROM_WIN32(status);

        const std::wstring providerPath = std::wstring(
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\") + clsid;
        status = RegDeleteTreeW(HKEY_LOCAL_MACHINE, providerPath.c_str());
        return (status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND) ? S_OK : HRESULT_FROM_WIN32(status);
    }

    class ClassFactory : public winrt::implements<ClassFactory, IClassFactory> {
    public:
        HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown* outer, REFIID iid, void** object) noexcept override {
            if (!object)
                return E_POINTER;
            *object = nullptr;
            if (outer)
                return CLASS_E_NOAGGREGATION;

            try {
                auto provider = winrt::make_self<CredentialProvider>();
                return provider->QueryInterface(iid, object);
            } catch (...) {
                return E_OUTOFMEMORY;
            }
        }

        HRESULT STDMETHODCALLTYPE LockServer(BOOL lock) noexcept override {
            if (lock)
                ++winrt::get_module_lock();
            else
                --winrt::get_module_lock();
            return S_OK;
        }
    };
}


extern "C" BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID /*reserved*/) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_moduleInstance = instance;
        DisableThreadLibraryCalls(instance);
    }
    return TRUE;
}

STDAPI DllCanUnloadNow() { return winrt::get_module_lock() ? S_FALSE : S_OK; }
STDAPI DllGetClassObject(REFCLSID clsid, REFIID iid, LPVOID* object) {
    if (!object)
        return E_POINTER;
    *object = nullptr;
    if (clsid != CLSID_ReversePasswordCredProv)
        return CLASS_E_CLASSNOTAVAILABLE;

    try {
        auto factory = winrt::make_self<ClassFactory>();
        return factory->QueryInterface(iid, object);
    } catch (...) {
        return E_OUTOFMEMORY;
    }
}
STDAPI DllRegisterServer() { return RegisterServer(); }
STDAPI DllUnregisterServer() { return UnregisterServer(); }
