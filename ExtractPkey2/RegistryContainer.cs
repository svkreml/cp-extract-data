using System;
using System.Security.Cryptography;
using System.Security.Principal;
using Microsoft.Win32;

namespace ExtractPkey
{
    internal class RegistryContainer : Container
    {
        private readonly string _containerName;

        public RegistryContainer(string containerName, string pin)
            : base(pin)
        {
            _containerName = containerName;
        }

        protected override Data LoadContainerData()
        {
            string keyName = GetCurrentUserKeyName(_containerName);
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(keyName))
            {
                if (key == null)
                    throw new CryptographicException($"Ключ \"HKLM\\{keyName}\" не найден.");

                return new Data
                {
                    Header = (byte[]) key.GetValue("header.key"),
                    Masks = (byte[]) key.GetValue("masks.key"),
                    Masks2 = (byte[]) key.GetValue("masks2.key"),
                    Name = (byte[]) key.GetValue("name.key"),
                    Primary = (byte[]) key.GetValue("primary.key"),
                    Primary2 = (byte[]) key.GetValue("primary2.key")
                };
            }
        }

        private static string GetCurrentUserKeyName(string containerName)
        {
            SecurityIdentifier securityIdentifier = WindowsIdentity.GetCurrent().User;
            if (securityIdentifier != null)
            {
                string sid = securityIdentifier.Value;
                string node = Environment.Is64BitOperatingSystem ? "Wow6432Node\\" : "";
                return string.Format(@"SOFTWARE\{0}Crypto Pro\Settings\Users\{1}\Keys\{2}", node, sid, containerName);
            } else
            {
                throw new NullReferenceException("WindowsIdentity.GetCurrent().User");
            }
        }
    }
}