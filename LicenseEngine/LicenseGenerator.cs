using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace IEplanPluginLicense.LicenseEngine
{
    public static class LicenseGenerator
    {
        public static (string PrivateKey, string PublicKey) GenerateKeyPair()
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                // ToXmlString(true) includes the private parameters (private key)
                string privateKey = rsa.ToXmlString(true);
                // ToXmlString(false) includes only the public parameters (public key)
                string publicKey = rsa.ToXmlString(false);
                return (privateKey, publicKey);
            }
        }

        public static string GenerateLicense(LicenseInfo info, string privateKeyXml)
        {
            if (info == null) 
                throw new ArgumentNullException(nameof(info));
            if (string.IsNullOrWhiteSpace(privateKeyXml)) 
                throw new ArgumentException("私钥 XML 不能为空。", nameof(privateKeyXml));

            // 序列化为 JSON 字符串并进行 Base64 编码
            string json = JsonSerializer.Serialize(info);
            string base64Json = Convert.ToBase64String(Encoding.UTF8.GetBytes(json));

            // 对 Base64 字符串的 UTF8 字节数组进行 RSA-SHA256 签名
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(privateKeyXml);
                byte[] dataBytes = Encoding.UTF8.GetBytes(base64Json);
                byte[] signatureBytes = rsa.SignData(dataBytes, CryptoConfig.MapNameToOID("SHA256")!);
                string base64Signature = Convert.ToBase64String(signatureBytes);

                return $"{base64Json}.{base64Signature}";
            }
        }
    }
}
