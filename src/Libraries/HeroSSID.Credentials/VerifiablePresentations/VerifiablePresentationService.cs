using System.Security.Cryptography;
using System.Text.Json;
using HeroSSID.Core.TenantManagement;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Data;
using HeroSSID.Infrastructure.KeyEncryption;
using HeroSSID.Infrastructure.RateLimiting;
using Microsoft.EntityFrameworkCore;

namespace HeroSSID.Credentials.VerifiablePresentations;

/// <summary>Full-disclosure holder proofs that retain and verify the original issuer-signed credential.</summary>
/// <remarks>Uses locally enrolled public identities and verifier-owned challenge policy; not an OpenID4VP endpoint.</remarks>
public sealed class VerifiablePresentationService : IVerifiablePresentationService
{
    private const int MaximumCredentialLength = 65_536;
    private const int MaximumPresentationLength = 131_072;
    private const string PresentationHeader = "{\"alg\":\"EdDSA\",\"typ\":\"vp+jwt\"}";
    private readonly HeroDbContext _dbContext;
    private readonly ICredentialVerificationService _credentialVerifier;
    private readonly IRateLimiter _rateLimiter;
    private readonly IKeyEncryptionService _keyEncryptionService;
    private readonly IPresentationChallengeStore _challenges;
    private readonly TimeProvider _timeProvider;

    /// <summary>Creates a presentation service. The challenge store must be shared between verifier scopes.</summary>
    public VerifiablePresentationService(
        HeroDbContext dbContext, ICredentialVerificationService credentialVerifier,
        IRateLimiter rateLimiter, IKeyEncryptionService keyEncryptionService,
        IPresentationChallengeStore challenges, TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(dbContext);
        ArgumentNullException.ThrowIfNull(credentialVerifier);
        ArgumentNullException.ThrowIfNull(rateLimiter);
        ArgumentNullException.ThrowIfNull(keyEncryptionService);
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(timeProvider);
        _dbContext = dbContext;
        _credentialVerifier = credentialVerifier;
        _rateLimiter = rateLimiter;
        _keyEncryptionService = keyEncryptionService;
        _challenges = challenges;
        _timeProvider = timeProvider;
    }

    /// <inheritdoc />
    public PresentationChallenge CreateChallenge(ITenantContext verifierContext, string audience, string trustedIssuerDid, TimeSpan? lifetime = null)
    {
        ArgumentNullException.ThrowIfNull(verifierContext);
        return _challenges.Issue(verifierContext.GetCurrentTenantId(), audience, trustedIssuerDid, lifetime);
    }

    /// <inheritdoc />
    public async Task<PresentationResult> CreatePresentationAsync(
        ITenantContext tenantContext, string credentialJwt, Guid holderDidId,
        PresentationChallenge challenge, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(tenantContext);
        ArgumentException.ThrowIfNullOrWhiteSpace(credentialJwt);
        ArgumentNullException.ThrowIfNull(challenge);
        var now = _timeProvider.GetUtcNow();
        if (string.IsNullOrWhiteSpace(challenge.Audience) || challenge.Audience.Length > 2048 ||
            string.IsNullOrWhiteSpace(challenge.TrustedIssuerDid) || challenge.TrustedIssuerDid.Length > 2048 ||
            string.IsNullOrEmpty(challenge.Nonce) || challenge.Nonce.Length != 43 ||
            challenge.ExpiresAt <= now || challenge.ExpiresAt > now.Add(InMemoryPresentationChallengeStore.MaximumLifetime))
        {
            throw new ArgumentException("A live, bounded verifier challenge is required.", nameof(challenge));
        }

        var tenantId = tenantContext.GetCurrentTenantId();
        if (tenantId == Guid.Empty)
        {
            throw new ArgumentException("A non-empty holder tenant is required.", nameof(tenantContext));
        }

        if (!await _rateLimiter.TryAcquireAsync(tenantId, "PRESENTATION_CREATE", cancellationToken).ConfigureAwait(false))
        {
            throw new InvalidOperationException("Rate limit exceeded for presentation creation.");
        }

        var holder = await _dbContext.Dids.AsNoTracking()
            .Where(d => d.Id == holderDidId && d.TenantId == tenantId)
            .Select(d => new { d.DidIdentifier, d.Status })
            .SingleOrDefaultAsync(cancellationToken).ConfigureAwait(false);
        if (holder == null || holder.Status != "active")
        {
            throw new ArgumentException("An active holder DID belonging to this tenant is required.", nameof(holderDidId));
        }

        var credential = await ValidateCredentialAsync(tenantContext, credentialJwt, holder.DidIdentifier, challenge.TrustedIssuerDid, cancellationToken).ConfigureAwait(false);
        if (!credential.IsValid)
        {
            throw new ArgumentException("The credential signature, issuer, holder, state or lifetime is invalid.", nameof(credentialJwt));
        }

        // Access the holder's encrypted key only after credential validation and tenant ownership checks.
        var encryptedKey = await _dbContext.Dids.AsNoTracking()
            .Where(d => d.Id == holderDidId && d.TenantId == tenantId && d.Status == "active")
            .Select(d => d.PrivateKeyEd25519Encrypted)
            .SingleOrDefaultAsync(cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException("The holder identity is no longer active.");
        now = _timeProvider.GetUtcNow();
        var expiresAt = Math.Min(challenge.ExpiresAt.ToUnixTimeSeconds(), credential.ExpiresAt?.ToUnixTimeSeconds() ?? long.MaxValue);
        if (expiresAt <= now.ToUnixTimeSeconds())
        {
            throw new ArgumentException("The challenge or credential has expired.", nameof(challenge));
        }

        var payload = JsonSerializer.Serialize(new
        {
            iss = holder.DidIdentifier,
            aud = challenge.Audience,
            nonce = challenge.Nonce,
            iat = now.ToUnixTimeSeconds(),
            exp = expiresAt,
            vp = new { verifiableCredential = new[] { credentialJwt } }
        });
        byte[]? privateKey = null;
        try
        {
            privateKey = _keyEncryptionService.Decrypt(encryptedKey);
            var jwt = Ed25519JwtSigner.CreateSignedJwt(PresentationHeader, payload, privateKey);
            return new PresentationResult
            {
                PresentationJwt = jwt,
                SelectedDisclosures = Array.Empty<string>(),
                DisclosedClaimNames = credential.CredentialSubject!.Keys.ToArray()
            };
        }
        finally
        {
            if (privateKey != null)
            {
                CryptographicOperations.ZeroMemory(privateKey);
            }
        }
    }

    /// <inheritdoc />
    public async Task<PresentationVerificationResult> VerifyPresentationAsync(
        ITenantContext verifierContext, string presentationJwt, string expectedAudience,
        string expectedNonce, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(verifierContext);
        if (string.IsNullOrWhiteSpace(presentationJwt) || string.IsNullOrWhiteSpace(expectedAudience) || string.IsNullOrWhiteSpace(expectedNonce))
        {
            return Failure(PresentationVerificationStatus.MalformedPresentation, "A presentation, expected audience and nonce are required.");
        }

        var verifierTenantId = verifierContext.GetCurrentTenantId();
        var challenge = _challenges.Find(verifierTenantId, expectedAudience, expectedNonce);
        if (challenge == null)
        {
            return Failure(PresentationVerificationStatus.ChallengeInvalid, "Unknown, expired, mismatched or consumed challenge.");
        }

        if (!StrictJwtReader.TryRead(presentationJwt, "vp+jwt", MaximumPresentationLength, out var payload) ||
            payload.EnumerateObject().Count() != 6 ||
            !StrictJwtReader.TryGetString(payload, "iss", out var holderDid) || holderDid.Length > 2048 ||
            !StrictJwtReader.TryGetString(payload, "aud", out var audience) || audience != expectedAudience ||
            !StrictJwtReader.TryGetString(payload, "nonce", out var nonce) || nonce != expectedNonce ||
            !StrictJwtReader.TryGetTimestamp(payload, "iat", out var issuedAt) ||
            !StrictJwtReader.TryGetTimestamp(payload, "exp", out var expiresAt) ||
            !payload.TryGetProperty("vp", out var vp) || vp.ValueKind != JsonValueKind.Object || vp.EnumerateObject().Count() != 1 ||
            !vp.TryGetProperty("verifiableCredential", out var credentials) || credentials.ValueKind != JsonValueKind.Array ||
            credentials.GetArrayLength() != 1 || credentials[0].ValueKind != JsonValueKind.String)
        {
            return Failure(PresentationVerificationStatus.MalformedPresentation, "Malformed or unbound full-disclosure presentation.");
        }

        var now = _timeProvider.GetUtcNow().ToUnixTimeSeconds();
        if (issuedAt > now || expiresAt <= now || expiresAt <= issuedAt || expiresAt - issuedAt > 300 ||
            expiresAt > challenge.ExpiresAt.ToUnixTimeSeconds())
        {
            return Failure(PresentationVerificationStatus.PresentationExpired, "Invalid presentation lifetime.");
        }

        // Only enrolled public fields are queried. Verifier tenant never grants holder signing authority.
        var holder = await _dbContext.Dids.AsNoTracking().Where(d => d.DidIdentifier == holderDid)
            .Select(d => new { d.PublicKeyEd25519, d.Status }).SingleOrDefaultAsync(cancellationToken).ConfigureAwait(false);
        if (holder == null || holder.Status != "active" || holder.PublicKeyEd25519.Length != 32)
        {
            return Failure(PresentationVerificationStatus.HolderInvalid, "An active enrolled holder key is required.");
        }

        if (!Ed25519JwtSigner.VerifySignedJwt(presentationJwt, holder.PublicKeyEd25519))
        {
            return Failure(PresentationVerificationStatus.PresentationSignatureInvalid, "The holder signature is invalid.");
        }

        var credential = await ValidateCredentialAsync(verifierContext, credentials[0].GetString()!, holderDid, challenge.TrustedIssuerDid, cancellationToken).ConfigureAwait(false);
        if (!credential.IsValid)
        {
            return Failure(PresentationVerificationStatus.CredentialInvalid, "The original credential signature, issuer, holder, state or lifetime is invalid.");
        }

        now = _timeProvider.GetUtcNow().ToUnixTimeSeconds();
        if (expiresAt <= now || (credential.ExpiresAt.HasValue &&
            (credential.ExpiresAt.Value.ToUnixTimeSeconds() <= now || expiresAt > credential.ExpiresAt.Value.ToUnixTimeSeconds())))
        {
            return Failure(PresentationVerificationStatus.PresentationExpired, "The presentation or credential expired during verification.");
        }

        cancellationToken.ThrowIfCancellationRequested();
        if (!_challenges.TryConsume(verifierTenantId, expectedAudience, expectedNonce))
        {
            return Failure(PresentationVerificationStatus.ChallengeInvalid, "The challenge expired or was already consumed.");
        }

        return new PresentationVerificationResult
        {
            IsValid = true,
            Status = PresentationVerificationStatus.Valid,
            ValidationErrors = Array.Empty<string>(),
            DisclosedClaims = credential.CredentialSubject,
            HolderDid = holderDid,
            IssuerDids = new[] { credential.IssuerDid! }
        };
    }

    /// <inheritdoc />
    public Task<PresentationResult> CreatePresentationAsync(
        ITenantContext tenantContext, string credentialJwt, string[]? claimsToDisclose,
        Guid holderDidId, string? audience = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(tenantContext);
        ArgumentException.ThrowIfNullOrWhiteSpace(credentialJwt);
        throw new NotSupportedException("Challenge-less and selective-disclosure presentations are unsupported. Use the full-disclosure overload with a verifier challenge.");
    }

    /// <inheritdoc />
    public Task<PresentationVerificationResult> VerifyPresentationAsync(
        ITenantContext tenantContext, string presentationJwt, string[] disclosureTokens,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(tenantContext);
        ArgumentException.ThrowIfNullOrWhiteSpace(presentationJwt);
        ArgumentNullException.ThrowIfNull(disclosureTokens);
        return Task.FromResult(Failure(PresentationVerificationStatus.ChallengeInvalid, "A verifier audience and issued challenge are required."));
    }

    private async Task<CredentialVerificationResult> ValidateCredentialAsync(
        ITenantContext requesterContext, string jwt, string holderDid, string trustedIssuerDid, CancellationToken cancellationToken)
    {
        var now = _timeProvider.GetUtcNow().ToUnixTimeSeconds();
        if (!StrictJwtReader.TryRead(jwt, "vc+jwt", MaximumCredentialLength, out var payload) ||
            !StrictJwtReader.TryGetString(payload, "iss", out var issuerDid) || issuerDid != trustedIssuerDid ||
            !StrictJwtReader.TryGetString(payload, "sub", out var subject) || subject != holderDid ||
            !StrictJwtReader.TryGetTimestamp(payload, "iat", out var issuedAt) || issuedAt > now ||
            !payload.TryGetProperty("vc", out var vc) || vc.ValueKind != JsonValueKind.Object ||
            !vc.TryGetProperty("credentialSubject", out var claims) || claims.ValueKind != JsonValueKind.Object ||
            (claims.TryGetProperty("id", out _) && (!StrictJwtReader.TryGetString(claims, "id", out var subjectId) || subjectId != holderDid)))
        {
            return InvalidCredential();
        }

        if (payload.TryGetProperty("nbf", out _) && (!StrictJwtReader.TryGetTimestamp(payload, "nbf", out var notBefore) || notBefore > now))
        {
            return InvalidCredential();
        }

        if (payload.TryGetProperty("exp", out var expiration) && expiration.ValueKind != JsonValueKind.Null &&
            (!StrictJwtReader.TryGetTimestamp(payload, "exp", out var expiresAt) || expiresAt <= now || expiresAt <= issuedAt))
        {
            return InvalidCredential();
        }

        // The unverified issuer is only a lookup hint. Its tenant comes from the enrolled public record.
        var issuer = await _dbContext.Dids.AsNoTracking().Where(d => d.DidIdentifier == issuerDid)
            .Select(d => new { d.TenantId, d.Status, d.PublicKeyEd25519 }).SingleOrDefaultAsync(cancellationToken).ConfigureAwait(false);
        if (issuer == null || issuer.TenantId == Guid.Empty || issuer.Status != "active" || issuer.PublicKeyEd25519.Length != 32)
        {
            return InvalidCredential();
        }

        return await _credentialVerifier.VerifyCredentialFromIssuerAsync(requesterContext, issuer.TenantId, jwt, cancellationToken).ConfigureAwait(false);
    }

    private static CredentialVerificationResult InvalidCredential() => new()
    {
        IsValid = false,
        Status = VerificationStatus.MalformedJwt,
        ValidationErrors = new[] { "Invalid credential for this presentation profile." }
    };

    private static PresentationVerificationResult Failure(PresentationVerificationStatus status, string message) => new()
    {
        IsValid = false,
        Status = status,
        ValidationErrors = new[] { message }
    };

}
