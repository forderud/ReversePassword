using System.Security.Principal;

namespace ReversePassword
{
    static class Common
    {
        //Determine authentication package required
        public static int RetrieveNegotiateAuthPackage(out uint authPackage)
        {
            Logger.Write();

            // establish LSA connection
            var status = PInvoke.LsaConnectUntrusted(out var lsaHandle);

            // use Negotiate to allow LSA to decide whether to use local or Kerberos authentication package
            using (var name = new PInvoke.LsaStringWrapper("Negotiate"))
            {
                status = PInvoke.LsaLookupAuthenticationPackage(lsaHandle, ref name._string, out authPackage);
            }

            // close LSA handle
            PInvoke.LsaDeregisterLogonProcess(lsaHandle);

            Logger.Write($"Using authentication package id: {authPackage}");

            return (int)status;
        }

        public static string GetNameFromSid(string value)
        {
            var sid = new SecurityIdentifier(value);
            var ntAccount = (NTAccount)sid.Translate(typeof(NTAccount));

            return ntAccount.ToString();
        }
    }
}
