namespace HeroSSID.DidOperations.Models;

/// <summary>
/// Result of retrieving a DID from the database by ID.
/// Similar to DidCreationResult but without sensitive private key material.
/// SECURITY: Implements IDisposable to allow callers to securely clear public key arrays from memory.
/// Always dispose of this object when done to ensure sensitive data is cleared.
/// </summary>
public sealed class DidRetrievalResult : IDisposable
{
    private bool _disposed;
    /// <summary>
    /// Internal database ID
    /// </summary>
    public required Guid Id { get; init; }

    /// <summary>
    /// Tenant ID
    /// </summary>
    public required Guid TenantId { get; init; }

    /// <summary>
    /// Full DID identifier (e.g., did:key:z6Mkf5rGMo...)
    /// </summary>
    public required string DidIdentifier { get; init; }

    /// <summary>
    /// Ed25519 public key (32 bytes)
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "DTO for cryptographic keys")]
    public required byte[] PublicKey { get; init; }

    /// <summary>
    /// W3C DID Document as JSON
    /// </summary>
    public required string DidDocumentJson { get; init; }

    /// <summary>
    /// DID status (e.g., "active", "revoked", "deactivated")
    /// </summary>
    public required string Status { get; init; }

    /// <summary>
    /// When the DID was created
    /// </summary>
    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary>
    /// Disposes the result and securely clears sensitive byte arrays from memory.
    /// SECURITY: This uses the same SecureZeroMemory approach as DidCreationResult
    /// to prevent sensitive data from remaining in memory or appearing in memory dumps.
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        // Securely clear sensitive byte array
        SecureZeroMemory(PublicKey);

        _disposed = true;
    }

    /// <summary>
    /// Securely zeros sensitive data from memory to prevent recovery from memory dumps.
    /// Uses unsafe code to pin the array and ensure the compiler doesn't optimize away the zeroing.
    /// </summary>
    /// <param name="buffer">The sensitive buffer to zero</param>
    private static void SecureZeroMemory(byte[] buffer)
    {
        if (buffer == null || buffer.Length == 0)
        {
            return;
        }

        // Pin the array in memory to prevent garbage collector from moving it
        System.Runtime.InteropServices.GCHandle handle = System.Runtime.InteropServices.GCHandle.Alloc(buffer, System.Runtime.InteropServices.GCHandleType.Pinned);
        try
        {
            // Use unsafe code to ensure zeroing isn't optimized away by the compiler
            unsafe
            {
                byte* ptr = (byte*)handle.AddrOfPinnedObject();
                for (int i = 0; i < buffer.Length; i++)
                {
                    ptr[i] = 0;
                }
            }
        }
        finally
        {
            handle.Free();
        }
    }
}
