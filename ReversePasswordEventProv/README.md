Custom Windows event provider. Used to enable custom log entry types throgh the legacy [Event Logging](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-logging)
API. The log schema is defined in message text files (.mc).

### Example log entries
<img width="1011" height="637" alt="image" src="https://github.com/user-attachments/assets/8d1465b1-195c-4173-9270-3eed7672cfe9" />

### Installation
The event provider DLL needs to be registered under `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Application\ReversePasswordEventProv` in the Windows registry to enable the Event Viewer app and APIs to parse log entries.

#### How to install
* Build project.
* Run `regsvr32.exe ReversePasswordEventProv.dll` from an admin command prompt to register the provider.

#### How to uninstall
* Run `regsvr32.exe /u ReversePasswordEventProv.dll` from an admin command prompt to unregister the provider.
