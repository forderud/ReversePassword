#pragma once
#include <Windows.h>


/** Return a listing of drives that are either removable (USB sticks) or CD-ROM'ish. */
static std::vector<std::wstring> GetRemovableDrives() {
    std::vector<wchar_t> buffer;
    {
        // Determine buffer size.
        DWORD bufferLength = GetLogicalDriveStringsW(0, nullptr);
        if (bufferLength == 0)
            abort();

        // Fetch the drive strings.
        // The strings are returned as a null-separated list ending with a double null terminator
        buffer.resize(bufferLength, L'\0');
        if (GetLogicalDriveStringsW(bufferLength, buffer.data()) == 0) {
            abort();
        }
    }

    std::vector<std::wstring> removable_drives;

    wchar_t* drivePtr = buffer.data();
    while (*drivePtr != L'\0') {
        // filter drives of either removable or CD-ROM type
        UINT driveType = GetDriveTypeW(drivePtr);
        if ((driveType == DRIVE_REMOVABLE) || (driveType == DRIVE_CDROM)) {
            removable_drives.push_back(drivePtr);
        }

        // Move pointer to the next drive string (skipping past the embedded null terminator)
        drivePtr += wcslen(drivePtr) + 1;
    }

    return removable_drives;
}


/** Check is the drive contains a magic file. */
static bool DriveHasMagicFile(std::wstring drive) {
    drive += L"\\*"; // add search suffix

    WIN32_FIND_DATAW match{};
    HANDLE search = FindFirstFileW(drive.c_str(), &match);
    if (search == INVALID_HANDLE_VALUE) {
        return false;
    }

    do {
        if (match.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            continue; // skip subfolders
        }

        std::wstring filename(match.cFileName);

        if (filename == L"DisablePasswordCheck") {
            // TODO: Also check file content
            FindClose(search);
            return true; // found magic file
        }
    } while (FindNextFileW(search, &match)); // Repeat while more files

    FindClose(search);
    return false;
}
