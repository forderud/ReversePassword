#pragma once
#include <string>
#include <vector>
#include <NTSecAPI.h> // for MSV1_0_INTERACTIVE_LOGON
#include <NTSecPKG.h> // for PLSA_CLIENT_REQUEST


std::vector<BYTE> PrepareProfileBuffer(const std::wstring& computername, const MSV1_0_INTERACTIVE_LOGON& logonInfo, PLSA_CLIENT_REQUEST ClientRequest, VOID** ProfileBuffer);
