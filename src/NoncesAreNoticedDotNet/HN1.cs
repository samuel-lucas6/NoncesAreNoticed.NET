using System.Security.Cryptography;
using System.Text;
using Geralt;

namespace NoncesAreNoticedDotNet;

public static class HN1
{
    public const int KeySize = AEGIS256.KeySize;
    public const int NonceSize = AEGIS256.NonceSize;
    public const int TagSize = AEGIS256.TagSize;
    private const string Context = "HN1[AEGIS-256,BLAKE2b-256]";

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.EqualToSize(nameof(ciphertext), ciphertext.Length, plaintext.Length + NonceSize + TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> okm = stackalloc byte[BLAKE2b.MaxHashSize], encKey = okm[..KeySize], prfKey = okm[KeySize..];
        // Could hash associatedData for context commitment
        BLAKE2b.ComputeTag(okm, Encoding.UTF8.GetBytes(Context), key);

        AEGIS256.Encrypt(ciphertext[NonceSize..], plaintext, nonce, encKey, associatedData);

        Span<byte> x = ciphertext.Slice(NonceSize, TagSize);
        Span<byte> p = stackalloc byte[NonceSize];
        BLAKE2b.ComputeTag(p, x, prfKey);

        for (int i = 0; i < NonceSize; i++) {
            ciphertext[i] = (byte)(p[i] ^ nonce[i]);
        }

        CryptographicOperations.ZeroMemory(okm);
        CryptographicOperations.ZeroMemory(p);
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.NotLessThanMin(nameof(ciphertext), ciphertext.Length, NonceSize + TagSize);
        Validation.EqualToSize(nameof(plaintext), plaintext.Length, ciphertext.Length - NonceSize - TagSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> okm = stackalloc byte[BLAKE2b.MaxHashSize], encKey = okm[..KeySize], prfKey = okm[KeySize..];
        BLAKE2b.ComputeTag(okm, Encoding.UTF8.GetBytes(Context), key);

        ReadOnlySpan<byte> x = ciphertext.Slice(NonceSize, TagSize);
        Span<byte> nonce = stackalloc byte[NonceSize];
        BLAKE2b.ComputeTag(nonce, x, prfKey);

        for (int i = 0; i < NonceSize; i++) {
            nonce[i] ^= ciphertext[i];
        }

        AEGIS256.Decrypt(plaintext, ciphertext[NonceSize..], nonce, encKey, associatedData);
        CryptographicOperations.ZeroMemory(okm);
        CryptographicOperations.ZeroMemory(nonce);
    }
}
