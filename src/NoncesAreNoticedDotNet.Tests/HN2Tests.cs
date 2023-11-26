namespace NoncesAreNoticedDotNet.Tests;

[TestClass]
public class HN2Tests
{
    public static IEnumerable<object[]> TestVectors()
    {
        yield return new object[]
        {
            "1cb1c4ad8381983ffdf81fe60ceaa521dfc0aea6f771fea470b2604f51a45c49cdaf3613e95a09b72a6e1cc7e13eb6c0ee2668598ba4a79e7f95b80906070e61c77a4755a564be360cf4c73959219fd5aa878130a6f820882723458a",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
            "cafebabefacedbaddecaf888",
            "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
            "acbef20579b4b8ebce889bac8732dad7"
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

        HN2.Encrypt(c, p, n, k, ad);

        Assert.AreEqual(ciphertext, Convert.ToHexString(c).ToLower());
    }

    [TestMethod]
    [DataRow(HN2.NonceSize + HN2.TagSize, 1, HN2.NonceSize, HN2.KeySize, HN2.TagSize)]
    [DataRow(HN2.NonceSize + HN2.TagSize, 0, HN2.NonceSize + 1, HN2.KeySize, HN2.TagSize)]
    [DataRow(HN2.NonceSize + HN2.TagSize, 0, HN2.NonceSize - 1, HN2.KeySize, HN2.TagSize)]
    [DataRow(HN2.NonceSize + HN2.TagSize, 0, HN2.NonceSize, HN2.KeySize + 1, HN2.TagSize)]
    [DataRow(HN2.NonceSize + HN2.TagSize, 0, HN2.NonceSize, HN2.KeySize - 1, HN2.TagSize)]
    public void Encrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, int associatedDataSize)
    {
        var c = new byte[ciphertextSize];
        var p = new byte[plaintextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];
        var ad = new byte[associatedDataSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => HN2.Encrypt(c, p, n, k, ad));
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        Span<byte> p = stackalloc byte[plaintext.Length / 2];
        Span<byte> c = Convert.FromHexString(ciphertext);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);

        HN2.Decrypt(p, c, k, ad);

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
            Assert.ThrowsException<AuthenticationTagMismatchException>(() => HN2.Decrypt(p, parameters[0], parameters[1], parameters[2]));
            param[0]--;
        }
        Assert.IsTrue(p.SequenceEqual(new byte[p.Length]));
    }

    [TestMethod]
    [DataRow(HN2.NonceSize + HN2.TagSize, 1, HN2.KeySize, HN2.TagSize)]
    [DataRow(HN2.NonceSize + HN2.TagSize, 0, HN2.KeySize + 1, HN2.TagSize)]
    [DataRow(HN2.NonceSize + HN2.TagSize, 0, HN2.KeySize - 1, HN2.TagSize)]
    public void Decrypt_Invalid(int ciphertextSize, int plaintextSize, int keySize, int associatedDataSize)
    {
        var p = new byte[plaintextSize];
        var c = new byte[ciphertextSize];
        var k = new byte[keySize];
        var ad = new byte[associatedDataSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => HN2.Decrypt(p, c, k, ad));
    }
}
