namespace NoncesAreNoticedDotNet.Tests;

[TestClass]
public class HN3Tests
{
    public static IEnumerable<object[]> TestVectors()
    {
        yield return new object[]
        {
            "0b86dace88f1100821a148fa3c1495a94aa525434b1e3f924bbf5ec6e721d9ec52c24cc126b197fa7d1cd5f9d9fa2132a43668074f29d564dd9a604b1ac5d2161195cb9107a370f3c9e5687f00f30fd503273876b9f2368297f398338a7ae9da",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "1000020000000000000000000000000000000000000000000000000000000000",
            "1001000000000000000000000000000000000000000000000000000000000000",
            "0001020304050607"
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

        HN3.Encrypt(c, p, n, k, ad);

        Assert.AreEqual(ciphertext, Convert.ToHexString(c).ToLower());
    }

    [TestMethod]
    [DataRow(HN3.NonceSize + HN3.TagSize, 1, HN3.NonceSize, HN3.KeySize, HN3.TagSize)]
    [DataRow(HN3.NonceSize + HN3.TagSize, 0, HN3.NonceSize + 1, HN3.KeySize, HN3.TagSize)]
    [DataRow(HN3.NonceSize + HN3.TagSize, 0, HN3.NonceSize - 1, HN3.KeySize, HN3.TagSize)]
    [DataRow(HN3.NonceSize + HN3.TagSize, 0, HN3.NonceSize, HN3.KeySize + 1, HN3.TagSize)]
    [DataRow(HN3.NonceSize + HN3.TagSize, 0, HN3.NonceSize, HN3.KeySize - 1, HN3.TagSize)]
    public void Encrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, int associatedDataSize)
    {
        var c = new byte[ciphertextSize];
        var p = new byte[plaintextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];
        var ad = new byte[associatedDataSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => HN3.Encrypt(c, p, n, k, ad));
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        Span<byte> p = stackalloc byte[plaintext.Length / 2];
        Span<byte> c = Convert.FromHexString(ciphertext);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);

        HN3.Decrypt(p, c, k, ad);

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
            Assert.ThrowsException<CryptographicException>(() => HN3.Decrypt(p, parameters[0], parameters[1], parameters[2]));
            param[0]--;
        }
        Assert.IsTrue(p.SequenceEqual(new byte[p.Length]));
    }

    [TestMethod]
    [DataRow(HN3.NonceSize + HN3.TagSize, 1, HN3.KeySize, HN3.TagSize)]
    [DataRow(HN3.NonceSize + HN3.TagSize, 0, HN3.KeySize + 1, HN3.TagSize)]
    [DataRow(HN3.NonceSize + HN3.TagSize, 0, HN3.KeySize - 1, HN3.TagSize)]
    public void Decrypt_Invalid(int ciphertextSize, int plaintextSize, int keySize, int associatedDataSize)
    {
        var p = new byte[plaintextSize];
        var c = new byte[ciphertextSize];
        var k = new byte[keySize];
        var ad = new byte[associatedDataSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => HN3.Decrypt(p, c, k, ad));
    }
}
