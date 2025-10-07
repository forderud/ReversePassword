namespace ReversePassword
{
    internal static class Constants
    {
        // The CLSID GUID is also hardcoded in install.reg
        public const string CredentialProvider_CLSID = "ACA40B06-9A9A-4B7B-A92C-F97FED8403B6";

        public const uint CREDENTIAL_PROVIDER_NO_DEFAULT = unchecked((uint)(-1));

        // from <winerror.h>
        public const uint ERROR_ACCESS_DENIED = 5;
        public const uint ERROR_INVALID_PASSWORD = 86;
        public const uint ERROR_CANT_ACCESS_DOMAIN_INFO = 1351;

        // from <ntstatus.h>
        public const uint STATUS_SUCCESS = 0x00000000;
        public const uint STATUS_NOT_IMPLEMENTED = 0xC0000002;
        public const uint STATUS_LOGON_FAILURE = 0xC000006D;
        public const uint STATUS_INTERNAL_ERROR = 0xC00000E5;

        // from <lmerr.h>
        public const uint NERR_Success = 0;
        public const uint NERR_BASE = 2100;
        public const uint NERR_UserNotFound = (NERR_BASE + 121);
        public const uint NERR_PasswordTooShort = (NERR_BASE + 145);
    }
}
