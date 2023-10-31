
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using static System.Convert;
namespace EncryptionAndDecryptionWebService.Data
{
    public class Protector
    {
        private static readonly byte[] salt = Encoding.Unicode.GetBytes("7BANANAS");
        private static readonly int iterations = 150_000;
        private static Dictionary<string, User> Users = new();

        public static string PublicKey { get; set; }




        public static async Task<string> Encrypt(string plainText, string password)
        {
            byte[] encryptedBytes;
            byte[] plainBytes = Encoding.Unicode.GetBytes(plainText);

            using (Aes aescrypt = Aes.Create())
            {
               
                Stopwatch timer = Stopwatch.StartNew();
                using (Rfc2898DeriveBytes pbkdf2 = new(password, salt, iterations, HashAlgorithmName.SHA256))
                {
                    aescrypt.Key = pbkdf2.GetBytes(32);
                    aescrypt.IV = pbkdf2.GetBytes(16);
                }
                timer.Stop();

                Console.WriteLine("{0:N0} milliseconds to generate Key and IV", timer.ElapsedMilliseconds);
                Console.WriteLine("Encryption algorithm:{0}-{1}, {2} mode with {3} padding.", "AES", aescrypt.KeySize, aescrypt.Mode, aescrypt.Padding);


                using MemoryStream ms = new();
                using ICryptoTransform transform = aescrypt.CreateEncryptor();
                using CryptoStream cs = new(ms, transform, CryptoStreamMode.Write);
                cs.Write(plainBytes, 0, plainBytes.Length);
                if (!cs.HasFlushedFinalBlock)
                {
                    await cs.FlushFinalBlockAsync();
                }
                encryptedBytes = ms.ToArray();
            }
            return ToBase64String(encryptedBytes);
        }


        public static async Task<string> Decrypt(string cipherText, string password)
        {
            byte[] plainBytes;
            byte[] cryptoBytes = FromBase64String(cipherText);

            using Aes aescrypt = Aes.Create();
            using Rfc2898DeriveBytes pbkdf2 = new(password, salt, iterations, HashAlgorithmName.SHA256);
            aescrypt.Key = pbkdf2.GetBytes(32);
            aescrypt.IV = pbkdf2.GetBytes(16);
            using MemoryStream ms = new();
            using ICryptoTransform transform = aescrypt.CreateDecryptor();
            using CryptoStream cs = new(ms, transform, CryptoStreamMode.Write);
            cs.Write(cryptoBytes, 0, cryptoBytes.Length);
            if (!cs.HasFlushedFinalBlock)
            {
                await cs.FlushFinalBlockAsync();
            }

            plainBytes = ms.ToArray();
            return Encoding.Unicode.GetString(plainBytes);
        }

        public static User Register(string username, string password)
        {
            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            byte[] saltBytes = new byte[16];
            rng.GetBytes(saltBytes);
            string saltText = ToBase64String(saltBytes);
            string saltedhashedPassword = SaltAndHashPassword(password, saltText);
            User user = new(username, saltText, saltedhashedPassword);
            Users.Add(user.Name, user);
            return user;

        }

        private static string SaltAndHashPassword(string password, string salt)
        {
            using SHA256 sha256 = SHA256.Create();
            string saltedPassword = password + salt;
            //ToBase64String(sha256.ComputeHash(FromBase64String(saltedPassword)));
            return ToBase64String(sha256.ComputeHash(Encoding.Unicode.GetBytes(saltedPassword)));
        }

        public static bool CheckPassword(string username, string password)
        {

            if (!Users.ContainsKey(username))
            {
                return false;
            }
            User u = Users[username];

            return CheckPassword(password, u.salt, u.SaltedHashedPassword);

        }

        public static bool CheckPassword(string password,string salt, string hashedPassword)
        {
            string saltedHashedPassword = SaltAndHashPassword(password, salt);
            return (saltedHashedPassword == hashedPassword);
        }


        public static string GenerateSignature(string data)
        {
            byte[] databytes = Encoding.Unicode.GetBytes(data);
            SHA256 sHA256 = SHA256.Create();
            byte[] hashedData= sHA256.ComputeHash(databytes);
            RSA rsa = RSA.Create();
            PublicKey = rsa.ToXmlString(false);
            return ToBase64String(rsa.SignHash(hashedData, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));

        }

        public static bool VerifySignature(string data, string signature)
        {
            if (PublicKey is null) return false;

            byte[] databytes = Encoding.Unicode.GetBytes(data);
            SHA256 sHA256 = SHA256.Create();
            byte[] hashedData = sHA256.ComputeHash(databytes);
            byte[] signatureBytes = FromBase64String(signature);
            RSA rsa = RSA.Create();
            rsa.FromXmlString(PublicKey);
            return rsa.VerifyHash(hashedData, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);


        }


    }
}
