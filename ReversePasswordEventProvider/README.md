Custom Windows event provider. Used to enable custom log entry types throgh the legacy [Event Logging](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-logging)
API. The log schema is defined in message text files (.mc).

### Example log entries
TODO

### Installation
The event provider DLL needs to be registered under `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Application\ReversePasswordEventProvider` in the Windows registry to enable the Event Viewer app and APIs to parse log entries.

#### How to install
* Build project.
* Run `regsvr32.exe ReversePasswordEventProvider.dll` from an admin command prompt to register the provider.

#### How to uninstall
* Run `regsvr32.exe /u ReversePasswordEventProvider.dll` from an admin command prompt to unregister the provider.
