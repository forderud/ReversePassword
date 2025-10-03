#pragma once
#include <Windows.h>
#include <BluetoothAPIs.h>  
#ifndef _WINDLL
  #include <stdio.h>
#endif

#pragma comment(lib, "Bthprops.lib")


void GetRadio(HANDLE* radio, HBLUETOOTH_RADIO_FIND* radioFind) {
    BLUETOOTH_FIND_RADIO_PARAMS parFinder{};
    parFinder.dwSize = sizeof(BLUETOOTH_FIND_RADIO_PARAMS);

    *radioFind = BluetoothFindFirstRadio(&parFinder, radio);

    BLUETOOTH_RADIO_INFO bri{};
    bri.dwSize = sizeof(BLUETOOTH_RADIO_INFO);

    if (BluetoothGetRadioInfo(*radio, &bri) != ERROR_SUCCESS) {
        CloseHandle(*radio);
        BluetoothFindRadioClose(*radioFind);
        *radio = NULL;
        *radioFind = NULL;
    }
}

bool HasBlueTooth() {
    HANDLE radio = 0;
    HBLUETOOTH_RADIO_FIND radioFinder = 0;
    GetRadio(&radio, &radioFinder);
    if (!radio)
        return false;

    BLUETOOTH_DEVICE_SEARCH_PARAMS par{};
    par.dwSize = sizeof(BLUETOOTH_DEVICE_SEARCH_PARAMS);
    par.hRadio = radio;
    par.fReturnAuthenticated = TRUE;
    par.fReturnConnected = TRUE;
    par.fReturnRemembered = TRUE;
    par.fReturnUnknown = TRUE;
    par.fIssueInquiry = TRUE;
    par.cTimeoutMultiplier = 3;

    BLUETOOTH_DEVICE_INFO_STRUCT info{};
    info.dwSize = sizeof(info);

    bool found = false;
    {
        HBLUETOOTH_DEVICE_FIND deviceFind = BluetoothFindFirstDevice(&par, &info);
        BOOL cont = (deviceFind != 0);
        while (cont) {
#ifndef _WINDLL
            wprintf(L"BlueTooth device: %s\n", info.szName);
#endif

            // TODO: Add BlueTooth device check based on "info" struct
            found = true;

            cont = BluetoothFindNextDevice(deviceFind, &info);
        }

        BluetoothFindDeviceClose(deviceFind);
    }

    CloseHandle(radio);
    BluetoothFindRadioClose(radioFinder);
    return found;
}
