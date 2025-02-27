using System.Security.Cryptography;
using System.Text;

public class Program
{
    public static void Main()
    {
        string publicKeyPem = File.ReadAllText("public_key.pem");
        string privateKeyPem = File.ReadAllText("private_key.pem");

        var rsaPublic = new RSACryptoServiceProvider();
        var rsaPrivate = new RSACryptoServiceProvider();

        rsaPublic.ImportFromPem(publicKeyPem.ToCharArray());

        // 加密
        string text = "Hello, RSA!";
        byte[] data = Encoding.UTF8.GetBytes(text);
        byte[] encryptedData = rsaPublic.Encrypt(data, RSAEncryptionPadding.Pkcs1);
        // 也不是非要用公钥加密
        // byte[] encryptedData = rsaPrivate.Encrypt(data, RSAEncryptionPadding.Pkcs1);
        string base64EncryptedData = Convert.ToBase64String(encryptedData);
        Console.WriteLine($"Encrypted data: {base64EncryptedData}");

        // 测试
        // string base64EncryptedData = "V0lDp1+uBm682YPna146AJ7VD7GfPryJr+QN1FRfRXy4iKQl/JmecbX1XpaYsQuxQ/52XiKRtvXbqfCfzhN8TUCY6rjzCFmKXuP5GcXQszzVBHXwIR/szvMblD60OHU/F35QEBpCB9HZTh7gNFRe7juJmh4ppeyQa3WY0VMK6bEC1L3r52sDAZUZukdtx3Xt3ZTuodL+WfYlr3nimvlrQMjlda3GLZ9JW8f+XlaWEpveoNBoXgHltYGQ4QRYTeYdWxJTOUBlVOi/meUSjGDaqswZlWRST4z9s9EdIcYc+PtNj2Fmov5GG9Fnrl5QbKjRQsU/Nz68ucIGSHm53SgFjQ==";
        // byte[] encryptedData = Convert.FromBase64String(base64EncryptedData);


        // 解密
        rsaPrivate.ImportFromPem(privateKeyPem.ToCharArray());
        byte[] decryptedData = rsaPrivate.Decrypt(encryptedData, RSAEncryptionPadding.Pkcs1);
        string decryptedText = Encoding.UTF8.GetString(decryptedData);
        Console.WriteLine($"Decrypted text: {decryptedText}");


    }
}