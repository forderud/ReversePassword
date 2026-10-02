; // Message Text File (.mc) with logging schema.
; // Based on https://learn.microsoft.com/en-us/windows/win32/eventlog/reporting-an-event

; // This is the header section.
SeverityNames=(Success=0x0:STATUS_SEVERITY_SUCCESS
               Informational=0x1:STATUS_SEVERITY_INFORMATIONAL
               Warning=0x2:STATUS_SEVERITY_WARNING
               Error=0x3:STATUS_SEVERITY_ERROR
              )


FacilityNames=(System=0x0:FACILITY_SYSTEM
               Runtime=0x2:FACILITY_RUNTIME
               Stubs=0x3:FACILITY_STUBS
               Io=0x4:FACILITY_IO_ERROR_CODE
              )

LanguageNames=(English=0x409:MSG00409)


; // The following are the categories of events.
; #define PROVIDER_CATEGORY_COUNT 3

MessageIdTypedef=WORD

MessageId=0x1
SymbolicName=AUTH_PKG_CATEGORY
Language=English
Authentication Package
.

MessageId=0x2
SymbolicName=CRED_PROVIDER_CATEGORY
Language=English
Credential Provider
.


; // The following are the message definitions.
MessageIdTypedef=DWORD

MessageId=0x100
Severity=Informational
Facility=Runtime
SymbolicName=MSG_CALL_SUCCESS
Language=English
Method "%1" succeeded.
.

MessageId=0x101
Severity=Error
Facility=Runtime
SymbolicName=MSG_CALL_FAILED
Language=English
Method "%1" failed, error: %2.
.
