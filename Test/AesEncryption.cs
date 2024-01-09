using System.Security.Cryptography;

namespace TimeCapsuleProof
{
  public class AesEncryption
  {
    public static byte[] Encrypt(byte[] plainBytes, byte[] key, byte[] iv)
    {
      using (Aes aesAlg = Aes.Create())
      {
        aesAlg.Key = key;
        aesAlg.IV = iv;
        ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
        var msEncrypt = new MemoryStream();
        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
          csEncrypt.Write(plainBytes, 0, plainBytes.Length);
        return msEncrypt.ToArray();
      }
    }
    public static byte[] Decrypt(byte[] cipherText, byte[] key, byte[] iv)
    {
      using (Aes aesAlg = Aes.Create())
      {
        aesAlg.Key = key;
        aesAlg.IV = iv;
        ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
        using (var msDecrypt = new MemoryStream(cipherText))
        using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
        using (var msPlain = new MemoryStream())
        {
          csDecrypt.CopyTo(msPlain);
          return msPlain.ToArray();
        }
      }
    }
  }
}
