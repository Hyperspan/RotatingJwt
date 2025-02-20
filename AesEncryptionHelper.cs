using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace RotatingJwt
{
    internal static class AesEncryptionHelper
    {
        private const int IvSize = 16; // 128 bits

        internal static string Encrypt(this string plainText, string keyString)
        {
            var key = ConvertKeyStringToBytes(keyString);

            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.GenerateIV(); // Generate a random IV

                using (var ms = new MemoryStream())
                {
                    ms.Write(aes.IV, 0, aes.IV.Length); // Prepend IV to the output

                    using (var cryptoStream = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    using (var writer = new StreamWriter(cryptoStream))
                    {
                        writer.Write(plainText);
                    }

                    return Convert.ToBase64String(ms.ToArray());
                }
            }
        }


        internal static string Decrypt(this string cipherTextWithIv, string keyString)
        {
            var key = ConvertKeyStringToBytes(keyString);

            using (var aes = Aes.Create())
            {
                var byteCipherText = Convert.FromBase64String(cipherTextWithIv);
                aes.Key = key;
                var iv = new byte[IvSize];
                Array.Copy(byteCipherText, 0, iv, 0, IvSize);
                aes.IV = iv;

                using (var ms = new MemoryStream(byteCipherText, IvSize, byteCipherText.Length - IvSize))
                using (var cryptoStream = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read))
                using (var reader = new StreamReader(cryptoStream))
                {
                    return reader.ReadToEnd();
                }
            }
        }

        /// <summary>
        /// Converts a string key (Base64 or hex) to a byte array.
        /// </summary>
        private static byte[] ConvertKeyStringToBytes(string keyString)
        {
            byte[] keyBytes;

            // Try decoding as Base64 first
            try
            {
                keyBytes = Convert.FromBase64String(keyString);
            }
            catch (FormatException)
            {
                throw new ArgumentException("Invalid AES key format. Ensure it's Base64 encoded.");
            }

            // Ensure the key is exactly 32 bytes
            if (keyBytes.Length != 32)
            {
                throw new ArgumentException("Key length must be exactly 32 bytes (256-bit AES).");
            }

            return keyBytes;
        }

        /// <summary>
        /// Converts a hex-encoded string to a byte array.
        /// </summary>
        private static byte[] ConvertHexStringToBytes(string hex)
        {
            if (hex.Length % 2 != 0)
            {
                throw new ArgumentException("Invalid hex string length.");
            }

            var bytes = new byte[hex.Length / 2];
            for (var i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return bytes;
        }
    }
}