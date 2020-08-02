using System.IO;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO.Pem;
using Org.BouncyCastle.X509;

namespace ExtractPkey
{
    internal interface IExport
    {
        void Export(Container container, Stream output);
    }

    internal class PrivateKeyExport : IExport
    {
        public void Export(Container container, Stream output)
        {
            Asn1Object privateKey = EncodePrivateKey(container);
            PemObject pemObject = new PemObject("PRIVATE KEY", privateKey.GetDerEncoded());
            using (StreamWriter sw = new StreamWriter(output))
            {
                PemWriter writer = new PemWriter(sw);
                writer.WriteObject(pemObject);
            }
        }

        private static Asn1Object EncodePrivateKey(Container container)
        {
            return new DerSequence(
                new DerInteger(0),
                new DerSequence(
                    container.SignAlgorithmId,
                    new DerSequence(
                        container.PublicKeyAlg.PublicKeyParamSet,
                        container.PublicKeyAlg.DigestParamSet
                    )
                ),
                new DerOctetString(new DerInteger(container.GetPrivateKey()))
            );
        }
    }

    internal class CertificateExport : IExport
    {
        public void Export(Container container, Stream output)
        {
            byte[] rawCert = container.GetRawCertificate();
            PemObject pemObject = new PemObject("CERTIFICATE", rawCert);
            using (StreamWriter sw = new StreamWriter(output))
            {
                PemWriter writer = new PemWriter(sw);
                writer.WriteObject(pemObject);
            }
        }
    }

    // не работает
    internal class Pkcs12Export : IExport
    {
        private readonly string _password;

        public Pkcs12Export(string password)
        {
            _password = password;
        }

        public void Export(Container container, Stream output)
        {
            byte[] rawCert = container.GetRawCertificate();
            BigInteger privateKey = container.GetPrivateKey();

            X509Certificate cert = new X509CertificateParser().ReadCertificate(rawCert);
            X509CertificateEntry certEntry = new X509CertificateEntry(cert);

            string friendlyName = "alias";
            Pkcs12Store store = new Pkcs12Store();
            store.SetCertificateEntry(friendlyName, certEntry);
            //store.SetKeyEntry(friendlyName, new AsymmetricKeyEntry(privateKey), new[] { certEntry });

            char[] password = _password.ToCharArray();
            using (MemoryStream ms = new MemoryStream())
            {
                store.Save(ms, password, new SecureRandom());

                // Save дописывает в конец какой-то мусор
                ms.Position = 0;
                Asn1InputStream asn1 = new Asn1InputStream(ms);
                Asn1Object result = asn1.ReadObject();
                byte[] buf = Pkcs12Utilities.ConvertToDefiniteLength(result.GetEncoded(), password);

                output.Write(buf, 0, buf.Length);
            }
        }
    }
}