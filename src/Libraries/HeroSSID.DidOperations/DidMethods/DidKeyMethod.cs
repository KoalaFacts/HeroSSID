using System.Text.Json;
using HeroSSID.Core.Interfaces;
using HeroSSID.Core.Models;
using HeroSSID.DidOperations.Helpers;

namespace HeroSSID.DidOperations.DidMethods;

/// <summary>
/// Implementation of the did:key method.
/// Generates DIDs from Ed25519 public keys using multibase/multicodec encoding.
/// Follows W3C did:key Method Specification.
/// </summary>
public sealed class DidKeyMethod : IDidMethod
{
    private static readonly JsonSerializerOptions s_jsonOptions = new()
    {
        WriteIndented = true
    };

    /// <inheritdoc />
    public string MethodName => "key";

    /// <inheritdoc />
    public string GenerateDidIdentifier(byte[] publicKey, Dictionary<string, object>? options = null)
    {
        ArgumentNullException.ThrowIfNull(publicKey);

        if (publicKey.Length != 32)
        {
            throw new ArgumentException("Public key must be 32 bytes for Ed25519", nameof(publicKey));
        }

        // 1. Add multicodec prefix (0xed01 for Ed25519-pub)
        byte[] multicodecKey = MulticodecHelper.AddEd25519Prefix(publicKey);

        // 2. Encode with Base58 Bitcoin alphabet
        string multibaseKey = SimpleBase.Base58.Bitcoin.Encode(multicodecKey);

        // 3. Add 'z' prefix for Base58 multibase encoding
        return $"did:key:z{multibaseKey}";
    }

    /// <inheritdoc />
    public string CreateDidDocument(string didIdentifier, byte[] publicKey, Dictionary<string, object>? options = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(didIdentifier);
        ArgumentNullException.ThrowIfNull(publicKey);

        if (!CanHandle(didIdentifier))
        {
            throw new ArgumentException($"DID identifier is not a valid did:key: {didIdentifier}", nameof(didIdentifier));
        }

        string publicKeyBase58 = SimpleBase.Base58.Bitcoin.Encode(publicKey);
        string verificationMethodId = $"{didIdentifier}#keys-1";

        DidDocument didDocument = new DidDocument
        {
            Context = new[]
            {
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1"
            },
            Id = didIdentifier,
            VerificationMethod = new[]
            {
                new VerificationMethod
                {
                    Id = verificationMethodId,
                    Type = "Ed25519VerificationKey2020",
                    Controller = didIdentifier,
                    PublicKeyMultibase = $"z{publicKeyBase58}"
                }
            },
            Authentication = new[] { verificationMethodId }
        };

        return JsonSerializer.Serialize(didDocument, s_jsonOptions);
    }

    /// <inheritdoc />
    public bool CanHandle(string did)
    {
        return did?.StartsWith("did:key:", StringComparison.Ordinal) == true;
    }

    /// <inheritdoc />
    public bool IsValid(string did)
    {
        if (!CanHandle(did))
        {
            return false;
        }

        try
        {
            // Extract the multibase portion (everything after "did:key:")
            string multibasePortion = did.Substring(8); // "did:key:".Length == 8

            // Must start with 'z' (Base58 multibase prefix)
            if (!multibasePortion.StartsWith('z'))
            {
                return false;
            }

            // Remove 'z' prefix and try to decode
            string base58Portion = multibasePortion.Substring(1);
            byte[] decoded = SimpleBase.Base58.Bitcoin.Decode(base58Portion);

            // Must have multicodec prefix + 32-byte public key = 34 bytes total
            if (decoded.Length != 34)
            {
                return false;
            }

            // Check for valid Ed25519 multicodec prefix (0xed, 0x01)
            if (decoded[0] != 0xed || decoded[1] != 0x01)
            {
                return false;
            }

            return true;
        }
#pragma warning disable CA1031 // Do not catch general exception types
        catch
#pragma warning restore CA1031
        {
            return false;
        }
    }
}
