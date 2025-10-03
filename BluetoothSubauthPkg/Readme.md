# Bluetooth subauthentication package
Sample MSV1_0 subauthentication package that will deny login if Bluetooth is enabled on the machine.


## Disable LSA protection
Local Security Authority (LSA) protection needs to be disabled in order for the autentication package DLL to load.

Instructions:
* Open "Windows Security"
* Click on "Device security"
* Click on "Core isolation"
* Turn off "Local Security Authority protection"

## Installation
Run `install.bat` as admin.
