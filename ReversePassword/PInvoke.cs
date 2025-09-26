using System.Runtime.InteropServices;

namespace ReversePassword
{
    static class PInvoke
    {
        //http://www.pinvoke.net/default.aspx/secur32/LsaLogonUser.html
        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_STRING
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public /*PCHAR*/ IntPtr Buffer;
        }

        public class LsaStringWrapper : IDisposable
        {
            public LSA_STRING _string;

            public LsaStringWrapper(string value)
            {
                _string = new LSA_STRING();
                _string.Length = (ushort)value.Length;
                _string.MaximumLength = (ushort)value.Length;
                _string.Buffer = Marshal.StringToHGlobalAnsi(value);
            }

            ~LsaStringWrapper()
            {
                Dispose(false);
            }

            private void Dispose(bool disposing)
            {
                if (_string.Buffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(_string.Buffer);
                    _string.Buffer = IntPtr.Zero;
                }
                if (disposing)
                    GC.SuppressFinalize(this);
            }

            public void Dispose()
            {
                Dispose(true);
            }
        }

        [DllImport("secur32.dll", SetLastError = false)]
        public static extern uint LsaConnectUntrusted([Out] out IntPtr lsaHandle);

        [DllImport("secur32.dll", SetLastError = false)]
        public static extern uint LsaLookupAuthenticationPackage([In] IntPtr lsaHandle, [In] ref LSA_STRING packageName, [Out] out UInt32 authenticationPackage);

        [DllImport("secur32.dll", SetLastError = false)]
        public static extern uint LsaDeregisterLogonProcess([In] IntPtr lsaHandle);

        [DllImport("credui.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CredPackAuthenticationBuffer(
            int dwFlags,
            string pszUserName,
            string pszPassword,
            IntPtr pPackedCredentials,
            ref int pcbPackedCredentials
        );

        public static bool CredPackAuthenticationBufferWrap(int flags,
            string username,
            string password,
            out IntPtr packedCredentials,
            out int packedCredentialsSize)
        {
            // first call to determine buffer size
            packedCredentials = Marshal.AllocCoTaskMem(0);
            packedCredentialsSize = 0;
            bool ok = PInvoke.CredPackAuthenticationBuffer(flags, username, password, packedCredentials, ref packedCredentialsSize);
            if (ok) // expected to fail
                return ok;

            // second call for actual packing
            Marshal.FreeCoTaskMem(packedCredentials);
            packedCredentials = Marshal.AllocCoTaskMem(packedCredentialsSize);
            return PInvoke.CredPackAuthenticationBuffer(flags, username, password, packedCredentials, ref packedCredentialsSize);
        }

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern uint NetUserChangePassword(
        [MarshalAs(UnmanagedType.LPWStr)] string domainname,
        [MarshalAs(UnmanagedType.LPWStr)] string username,
        [MarshalAs(UnmanagedType.LPWStr)] string oldpassword,
        [MarshalAs(UnmanagedType.LPWStr)] string newpassword);
    }
}
