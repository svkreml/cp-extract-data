using System.Security.Cryptography;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Rosstandart;

namespace ExtractPkey
{
    internal static class Utils
    {
        private static readonly DerObjectIdentifier GostR3410_2001DH =
            new DerObjectIdentifier(CryptoProObjectIdentifiers.GostID + ".98");

        public static ProviderType GetProviderType(DerObjectIdentifier algId)
        {
            if (algId.Equals(GostR3410_2001DH))
                return ProviderType.CryptoPro_2001;
            if (algId.Equals(RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_256))
                return ProviderType.CryptoPro_2012_512;
            if (algId.Equals(RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_512))
                return ProviderType.CryptoPro_2012_1024;

            throw new CryptographicException($"Неподдерживаемый OID: {algId}.");
        }

        public static DerObjectIdentifier GetSignAlgorithmId(ProviderType provider)
        {
            switch (provider)
            {
                case ProviderType.CryptoPro_2001:
                    return CryptoProObjectIdentifiers.GostR3410x2001;
                case ProviderType.CryptoPro_2012_512:
                    return RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256;
                case ProviderType.CryptoPro_2012_1024:
                    return RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512;
                default:
                    throw new CryptographicException($"Неподдерживаемый криптопровайдер: {provider}.");
            }
        }
    }
}