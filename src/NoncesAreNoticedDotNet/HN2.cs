using System.Security.Cryptography;
using System.Text;
using Geralt;

namespace NoncesAreNoticedDotNet;

public static class HN2
{
    public const int KeySize = 32;
    public const int NonceSize = 12;
    public const int TagSize = 16;
    private const int BlockSize = 16;
    private const string Info = "HN2[AES-GCM,32,AES,SplitFirst]";

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.EqualToSize(nameof(ciphertext), ciphertext.Length, plaintext.Length + NonceSize + TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> okm = stackalloc byte[KeySize * 2], encKey = okm[..KeySize], prfKey = okm[KeySize..];
        HKDF.Expand(HashAlgorithmName.SHA256, key, okm, Encoding.UTF8.GetBytes(Info));

        using var aesGcm = new AesGcm(encKey, TagSize);
        aesGcm.Encrypt(nonce, plaintext, ciphertext[NonceSize..^TagSize], ciphertext[^TagSize..], associatedData);

        Span<byte> x = ciphertext.Slice(NonceSize, BlockSize - NonceSize);
        Span<byte> nonceBlock = stackalloc byte[BlockSize];
        nonce.CopyTo(nonceBlock);
        x.CopyTo(nonceBlock[NonceSize..]);

        using var aes = Aes.Create();
        aes.Key = prfKey.ToArray();
        aes.EncryptEcb(nonceBlock, ciphertext[..BlockSize], PaddingMode.None);

        CryptographicOperations.ZeroMemory(okm);
        CryptographicOperations.ZeroMemory(nonceBlock);
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.NotLessThanMin(nameof(ciphertext), ciphertext.Length, NonceSize + TagSize);
        Validation.EqualToSize(nameof(plaintext), plaintext.Length, ciphertext.Length - NonceSize - TagSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> okm = stackalloc byte[KeySize * 2], encKey = okm[..KeySize], prfKey = okm[KeySize..];
        HKDF.Expand(HashAlgorithmName.SHA256, key, okm, Encoding.UTF8.GetBytes(Info));

        Span<byte> fullCiphertext = new byte[ciphertext.Length], decryptedBlock = fullCiphertext[..BlockSize], nonce = decryptedBlock[..NonceSize];
        using var aes = Aes.Create();
        aes.Key = prfKey.ToArray();
        aes.DecryptEcb(ciphertext[..BlockSize], decryptedBlock, PaddingMode.None);

        ciphertext[BlockSize..].CopyTo(fullCiphertext[BlockSize..]);
        using var aesGcm = new AesGcm(encKey, TagSize);
        aesGcm.Decrypt(nonce, fullCiphertext[NonceSize..^TagSize], fullCiphertext[^TagSize..], plaintext, associatedData);

        CryptographicOperations.ZeroMemory(okm);
        CryptographicOperations.ZeroMemory(decryptedBlock);
    }
}
