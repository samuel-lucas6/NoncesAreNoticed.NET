using System.Security.Cryptography;
using System.Text;
using Geralt;

namespace NoncesAreNoticedDotNet;

public static class HN3
{
    public const int KeySize = AEGIS256.KeySize;
    public const int NonceSize = AEGIS256.NonceSize;
    public const int TagSize = AEGIS256.TagSize;
    private const string Context = "HN3[AEGIS-256,BLAKE2b-256]";

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.EqualToSize(nameof(ciphertext), ciphertext.Length, plaintext.Length + NonceSize + TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> okm = stackalloc byte[BLAKE2b.MaxHashSize], prfKey = okm[..KeySize], encKey = okm[KeySize..];
        BLAKE2b.ComputeTag(okm, Encoding.UTF8.GetBytes(Context), key);

        Span<byte> syntheticNonce = ciphertext[..NonceSize];
        BLAKE2b.ComputeTag(syntheticNonce, nonce, prfKey);

        AEGIS256.Encrypt(ciphertext[NonceSize..], plaintext, syntheticNonce, encKey, associatedData);
        CryptographicOperations.ZeroMemory(okm);
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.NotLessThanMin(nameof(ciphertext), ciphertext.Length, NonceSize + TagSize);
        Validation.EqualToSize(nameof(plaintext), plaintext.Length, ciphertext.Length - NonceSize - TagSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> okm = stackalloc byte[BLAKE2b.MaxHashSize], encKey = okm[KeySize..];
        BLAKE2b.ComputeTag(okm, Encoding.UTF8.GetBytes(Context), key);

        ReadOnlySpan<byte> syntheticNonce = ciphertext[..NonceSize];
        AEGIS256.Decrypt(plaintext, ciphertext[NonceSize..], syntheticNonce, encKey, associatedData);
        CryptographicOperations.ZeroMemory(okm);
    }
}
