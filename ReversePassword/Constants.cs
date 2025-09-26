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

        // from <lmerr.h>
        public const uint NERR_Success = 0;
        public const uint NERR_BASE = 2100;
        public const uint NERR_UserNotFound = (NERR_BASE + 121);
        public const uint NERR_PasswordTooShort = (NERR_BASE + 145);
    }
}
