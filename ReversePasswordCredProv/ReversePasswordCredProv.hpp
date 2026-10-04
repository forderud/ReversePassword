#pragma once
#include "resource.h"
#include <Windows.h>
#include <credentialprovider.h>
#include <atlbase.h>
#include <atlcom.h>

#include <memory>
#include <string>
#include <variant>
#include <vector>


constexpr DWORD ICON_FIELD = 0;
constexpr DWORD USERNAME_FIELD = 1;
constexpr DWORD PASSWORD_FIELD = 2;
constexpr DWORD NEW_PASSWORD_FIELD = 3;
constexpr DWORD SUBMIT_BUTTON_FIELD = 4;
constexpr NTSTATUS STATUS_SUCCESS = static_cast<NTSTATUS>(0); // instead of <ntstatus.h> include


const CLSID CLSID_ReversePasswordCredProv =
{ 0xaca40b06, 0x9a9a, 0x4b7b, { 0xa9, 0x2c, 0xf9, 0x7f, 0xed, 0x84, 0x03, 0xb6 } };


struct Field {
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR descriptor{};
    CREDENTIAL_PROVIDER_FIELD_STATE state{};
    std::variant<std::wstring, DWORD> value;
};

struct CredentialView {
    CREDENTIAL_PROVIDER_USAGE_SCENARIO usage{};
    std::vector<Field> fields;
};


inline WCHAR* DuplicateString(const WCHAR* source) {
    if (!source)
        return nullptr;

    WCHAR* result = nullptr;
    HRESULT hr = SHStrDupW(source, &result); // uses CoTaskMemAlloc internally
    if (FAILED(hr))
        return nullptr;

    return result;
}
