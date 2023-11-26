namespace NoncesAreNoticedDotNet.Tests;

[TestClass]
public class HN1Tests
{
    public static IEnumerable<object[]> TestVectors()
    {
        yield return new object[]
        {
            "ffd122cfc6ab85c2484fb018879b92084faf85cf61abc5686fc870c3afa82523ffd4f4aa8836b8dc8ae5252bc47d3a4db5e9ce130e277eb11dcec267bb3f300faa239f28522d7e8ce6858b95535d435b2ea2ee92eb7cec03bdbedac0206d1823",
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

        HN1.Encrypt(c, p, n, k, ad);

        Assert.AreEqual(ciphertext, Convert.ToHexString(c).ToLower());
    }

    [TestMethod]
    [DataRow(HN1.NonceSize + HN1.TagSize, 1, HN1.NonceSize, HN1.KeySize, HN1.TagSize)]
    [DataRow(HN1.NonceSize + HN1.TagSize, 0, HN1.NonceSize + 1, HN1.KeySize, HN1.TagSize)]
    [DataRow(HN1.NonceSize + HN1.TagSize, 0, HN1.NonceSize - 1, HN1.KeySize, HN1.TagSize)]
    [DataRow(HN1.NonceSize + HN1.TagSize, 0, HN1.NonceSize, HN1.KeySize + 1, HN1.TagSize)]
    [DataRow(HN1.NonceSize + HN1.TagSize, 0, HN1.NonceSize, HN1.KeySize - 1, HN1.TagSize)]
    public void Encrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, int associatedDataSize)
    {
        var c = new byte[ciphertextSize];
        var p = new byte[plaintextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];
        var ad = new byte[associatedDataSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => HN1.Encrypt(c, p, n, k, ad));
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        Span<byte> p = stackalloc byte[plaintext.Length / 2];
        Span<byte> c = Convert.FromHexString(ciphertext);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);

        HN1.Decrypt(p, c, k, ad);

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
            Assert.ThrowsException<CryptographicException>(() => HN1.Decrypt(p, parameters[0], parameters[1], parameters[2]));
            param[0]--;
        }
        Assert.IsTrue(p.SequenceEqual(new byte[p.Length]));
    }

    [TestMethod]
    [DataRow(HN1.NonceSize + HN1.TagSize, 1, HN1.KeySize, HN1.TagSize)]
    [DataRow(HN1.NonceSize + HN1.TagSize, 0, HN1.KeySize + 1, HN1.TagSize)]
    [DataRow(HN1.NonceSize + HN1.TagSize, 0, HN1.KeySize - 1, HN1.TagSize)]
    public void Decrypt_Invalid(int ciphertextSize, int plaintextSize, int keySize, int associatedDataSize)
    {
        var p = new byte[plaintextSize];
        var c = new byte[ciphertextSize];
        var k = new byte[keySize];
        var ad = new byte[associatedDataSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => HN1.Decrypt(p, c, k, ad));
    }
}
