namespace NoncesAreNoticedDotNet.Tests;

[TestClass]
public class HN4Tests
{
    public static IEnumerable<object[]> TestVectors()
    {
        yield return new object[]
        {
            "3d9d7cdc255022784d81e0bea56f7fa964f6bf7b91569ff6107045a3d4dd0daa3ecaeb70a8976739752bb7f8e05eb5ee6420f3a47cc8d4c2582260a5dc57b902d6c56c89a13d2c9ce82564ff02fda7d734700a2ca054a10d4f7d6bd423d7fffa99ee6ebdae1d2573bc8395d23d570ce2243e71c2624cf7cfa49074d0ab9407542e041a1a3b80cdd10a6217b2f51607c1a54d8306f0001fa1aa91b4cb785b0c1487d9cdd2c0f20f908c1c",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
            "404142434445464748494a4b4c4d4e4f5051525354555657",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "50515253c0c1c2c3c4c5c6c7"
        };
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Encrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        Span<byte> c = stackalloc byte[ciphertext.Length / 2];
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);

        HN4.Encrypt(c, p, n, k, ad);

        Assert.AreEqual(ciphertext, Convert.ToHexString(c).ToLower());
    }

    [TestMethod]
    [DataRow(HN4.NonceSize + HN4.TagSize, 1, HN4.NonceSize, HN4.KeySize, HN4.TagSize)]
    [DataRow(HN4.NonceSize + HN4.TagSize, 0, HN4.NonceSize + 1, HN4.KeySize, HN4.TagSize)]
    [DataRow(HN4.NonceSize + HN4.TagSize, 0, HN4.NonceSize - 1, HN4.KeySize, HN4.TagSize)]
    [DataRow(HN4.NonceSize + HN4.TagSize, 0, HN4.NonceSize, HN4.KeySize + 1, HN4.TagSize)]
    [DataRow(HN4.NonceSize + HN4.TagSize, 0, HN4.NonceSize, HN4.KeySize - 1, HN4.TagSize)]
    public void Encrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, int associatedDataSize)
    {
        var c = new byte[ciphertextSize];
        var p = new byte[plaintextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];
        var ad = new byte[associatedDataSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => HN4.Encrypt(c, p, n, k, ad));
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        Span<byte> p = stackalloc byte[plaintext.Length / 2];
        Span<byte> c = Convert.FromHexString(ciphertext);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);

        HN4.Decrypt(p, c, k, ad);

        Assert.AreEqual(plaintext, Convert.ToHexString(p).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Tampered(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        var p = new byte[plaintext.Length / 2];
        var parameters = new List<byte[]>
        {
            Convert.FromHexString(ciphertext),
            Convert.FromHexString(key),
            Convert.FromHexString(associatedData)
        };

        foreach (var param in parameters.Where(param => param.Length > 0)) {
            param[0]++;
            Assert.ThrowsException<CryptographicException>(() => HN4.Decrypt(p, parameters[0], parameters[1], parameters[2]));
            param[0]--;
        }
        Assert.IsTrue(p.SequenceEqual(new byte[p.Length]));
    }

    [TestMethod]
    [DataRow(HN4.NonceSize + HN4.TagSize, 1, HN4.KeySize, HN4.TagSize)]
    [DataRow(HN4.NonceSize + HN4.TagSize, 0, HN4.KeySize + 1, HN4.TagSize)]
    [DataRow(HN4.NonceSize + HN4.TagSize, 0, HN4.KeySize - 1, HN4.TagSize)]
    public void Decrypt_Invalid(int ciphertextSize, int plaintextSize, int keySize, int associatedDataSize)
    {
        var p = new byte[plaintextSize];
        var c = new byte[ciphertextSize];
        var k = new byte[keySize];
        var ad = new byte[associatedDataSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => HN4.Decrypt(p, c, k, ad));
    }
}
