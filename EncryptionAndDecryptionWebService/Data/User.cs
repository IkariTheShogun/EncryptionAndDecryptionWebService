namespace EncryptionAndDecryptionWebService.Data
{
    public  record class User(string Name, string salt, string SaltedHashedPassword);
}
