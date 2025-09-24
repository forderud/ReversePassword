using System.Diagnostics;

namespace ReversePassword
{
    internal static class Logger
    {
        private static string s_path;
        private static readonly object s_signal = new object();

        public static void Write(string line = null, string caller = null)
        {
            if (string.IsNullOrWhiteSpace(caller))
            {
                var method = new StackTrace().GetFrame(1).GetMethod();
                caller = $"{method.DeclaringType?.Name}.{method.Name}";
            }

            var log = $"{DateTimeOffset.UtcNow:u} [{caller}]";

            if (!string.IsNullOrWhiteSpace(line))
                log += " " + line;

            //Just in case multiple threads try to write to the log
            lock (s_signal)
            {
                Console.WriteLine(log);
                try
                {
                    var filePath = GetFilePath();
                    File.AppendAllText(filePath, log + Environment.NewLine);
                }
                catch (UnauthorizedAccessException) {
                    // ignore log-file exceptions if running CredUITester.exe as non-admin
                }
            }
        }

        private static string GetFilePath()
        {
            if (s_path == null)
            {
                var folder = $"{Environment.GetFolderPath(Environment.SpecialFolder.Windows)}\\Logs\\ReversePassword";

                if (!Directory.Exists(folder))
                    Directory.CreateDirectory(folder);

                s_path = $"{folder}\\Log-{DateTime.Now.Ticks}.txt";
            }

            return s_path;
        }
    }
}
