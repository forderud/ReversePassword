#pragma once

void LogMessage(const char* message, ...) {
    // append to log file
    FILE* file = nullptr;
    fopen_s(&file, "C:\\CustomAuthPkg_log.txt", "a+");
    {
        // print variadic message
        va_list args;
        va_start(args, message);
        _vfprintf_l(file, message, NULL, args);
        va_end(args);
    }
    fprintf(file, "\n");
    fclose(file);
}

/** Allocate and create a new LSA_STRING object.
    Assumes that "FunctionTable" is initialized. */
LSA_STRING* CreateLsaString(const std::string& msg) {
    auto msg_len = (USHORT)msg.size(); // exclude null-termination

    assert(FunctionTable.AllocateLsaHeap);
    auto* obj = (LSA_STRING*)FunctionTable.AllocateLsaHeap(sizeof(LSA_STRING));
    obj->Buffer = (char*)FunctionTable.AllocateLsaHeap(msg_len);
    memcpy(/*dst*/obj->Buffer, /*src*/msg.c_str(), msg_len);
    obj->Length = msg_len;
    obj->MaximumLength = msg_len;
    return obj;
}

/** Allocate and create a new LSA_UNICODE_STRING object.
    Assumes that "FunctionTable" is initialized. */
LSA_UNICODE_STRING* CreateLsaString(const std::wstring& msg) {
    auto msg_len = (USHORT)msg.size(); // exclude null-termination

    assert(FunctionTable.AllocateLsaHeap);
    auto* obj = (LSA_UNICODE_STRING*)FunctionTable.AllocateLsaHeap(sizeof(LSA_UNICODE_STRING));
    obj->Buffer = (wchar_t*)FunctionTable.AllocateLsaHeap(2 * msg_len);
    memcpy(/*dst*/obj->Buffer, /*src*/msg.c_str(), 2 * msg_len);
    obj->Length = 2 * msg_len;
    obj->MaximumLength = 2 * msg_len;
    return obj;
}
