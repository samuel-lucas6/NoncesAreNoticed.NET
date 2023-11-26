using System.Security.Cryptography;
using System.Buffers.Binary;
using System.Text;
using Geralt;

namespace NoncesAreNoticedDotNet;

public static class HN4
{
    public const int KeySize = XChaCha20.KeySize;
    public const int NonceSize = XChaCha20.NonceSize;
    public const int TagSize = BLAKE2b.TagSize;
    private const string Context = "HN4[XChaCha20,192,BLAKE2b-256]";

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.EqualToSize(nameof(ciphertext), ciphertext.Length, plaintext.Length + NonceSize + TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> okm = stackalloc byte[BLAKE2b.MaxHashSize], prfKey = okm[..KeySize], encKey = okm[KeySize..];
        BLAKE2b.ComputeTag(okm, Encoding.UTF8.GetBytes(Context), key);

        Span<byte> tag = ciphertext[..TagSize];
        Span<byte> lengths = stackalloc byte[16];
        using var blake2b = new IncrementalBLAKE2b(TagSize, prfKey);
        blake2b.Update(nonce);
        // These have variable lengths - could use associatedData in key derivation
        blake2b.Update(plaintext);
        blake2b.Update(associatedData);
        BinaryPrimitives.WriteUInt64LittleEndian(lengths[..8], (ulong)plaintext.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(lengths[8..], (ulong)associatedData.Length);
        blake2b.Update(lengths);
        blake2b.Finalize(tag);

        Span<byte> newPlaintext = new byte[plaintext.Length + NonceSize];
        nonce.CopyTo(newPlaintext);
        plaintext.CopyTo(newPlaintext[NonceSize..]);
        // The paper specifies associatedData here, but that would lead to two tags unnecessarily
        XChaCha20.Encrypt(ciphertext[TagSize..], newPlaintext, tag[..NonceSize], encKey);

        CryptographicOperations.ZeroMemory(okm);
        CryptographicOperations.ZeroMemory(lengths);
        CryptographicOperations.ZeroMemory(newPlaintext);
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.NotLessThanMin(nameof(ciphertext), ciphertext.Length, NonceSize + TagSize);
        Validation.EqualToSize(nameof(plaintext), plaintext.Length, ciphertext.Length - NonceSize - TagSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> okm = stackalloc byte[BLAKE2b.MaxHashSize], prfKey = okm[..KeySize], encKey = okm[KeySize..];
        BLAKE2b.ComputeTag(okm, Encoding.UTF8.GetBytes(Context), key);

        ReadOnlySpan<byte> tag = ciphertext[..TagSize];
        Span<byte> tempPlaintext = new byte[plaintext.Length + NonceSize];
        XChaCha20.Decrypt(tempPlaintext, ciphertext[TagSize..], tag[..NonceSize], encKey);

        Span<byte> nonce = tempPlaintext[..NonceSize], message = tempPlaintext[NonceSize..];
        Span<byte> lengths = stackalloc byte[16];
        using var blake2b = new IncrementalBLAKE2b(TagSize, prfKey);
        blake2b.Update(nonce);
        blake2b.Update(message);
        blake2b.Update(associatedData);
        BinaryPrimitives.WriteUInt64LittleEndian(lengths[..8], (ulong)message.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(lengths[8..], (ulong)associatedData.Length);
        blake2b.Update(lengths);

        bool valid = blake2b.FinalizeAndVerify(tag);
        CryptographicOperations.ZeroMemory(okm);
        if (!valid) {
            CryptographicOperations.ZeroMemory(tempPlaintext);
            throw new CryptographicException();
        }
        message.CopyTo(plaintext);
    }
}
