using System.Text.Json;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Credentials.Vcdm20;

/// <summary>
/// Distributed creation of the private HeroSSID lost-issuer-key recovery evidence.
/// Each signer retains its own private seed. Coordinators handle only signed JWTs.
/// No method here consumes a challenge, transfers DID control, changes a trust pin
/// or grants organizational recovery authority.
/// </summary>
public static class IssuerGuardianRecoveryDistributed
{
    private const string HeaderType = "herossid-issuer-guardian-recovery+jwt";
    private const string Purpose = "issuer-key-guardian-recovery";
    private const int MaximumJwtLength = 4_096;
    private const int MaximumEvidenceLength = 32_768;
    private const decimal LifetimeSeconds = 300m;

    /// <summary>
    /// The proposed successor signs the initial exact five-minute recovery
    /// statement locally, without importing or collecting any guardian seed.
    /// The relying party must issue and own the HTTPS audience and nonce.
    /// </summary>
    public static string CreateSuccessorSignature(string previousIssuerDid,
        string successorIssuerDid, byte[] successorSeed, Uri verifierAudience,
        string nonce, TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(previousIssuerDid);
        ArgumentNullException.ThrowIfNull(successorIssuerDid);
        ArgumentNullException.ThrowIfNull(successorSeed);
        ArgumentNullException.ThrowIfNull(verifierAudience);
        ArgumentNullException.ThrowIfNull(nonce);
        ArgumentNullException.ThrowIfNull(clock);

        if (!OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(previousIssuerDid, out _) ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(successorIssuerDid, out byte[] successorPublicKey) ||
            string.Equals(previousIssuerDid, successorIssuerDid, StringComparison.Ordinal) ||
            successorSeed.Length != 32 || successorSeed.All(static b => b == 0) ||
            !ValidAudience(verifierAudience) || !ValidNonce(nonce))
        {
            throw new ArgumentException("Distinct issuer keys, a valid successor seed, HTTPS verifier and strong nonce are required.");
        }

        decimal issued = PresentationChallengePolicy.NumericDate(clock.GetUtcNow());
        decimal expires = issued + LifetimeSeconds;
        if (issued < 0m || expires >= 253402300800m)
        {
            throw new ArgumentException("The recovery evidence clock is outside the supported UTC range.", nameof(clock));
        }

        string statement = JsonSerializer.Serialize(new
        {
            version = 1,
            purpose = Purpose,
            previousIssuer = previousIssuerDid,
            successorIssuer = successorIssuerDid,
            aud = verifierAudience.AbsoluteUri,
            nonce,
            iat = issued,
            exp = expires
        });
        string signature = Ed25519JwtSigner.CreateSignedJwt(Header(successorIssuerDid),
            statement, successorSeed);
        if (signature.Length > MaximumJwtLength ||
            !Ed25519JwtSigner.VerifySignedJwt(signature, successorPublicKey))
        {
            throw new ArgumentException("The successor seed does not control the declared new issuer DID.", nameof(successorSeed));
        }

        return signature;
    }

    /// <summary>
    /// Independently validate the successor's genuine signed proposal against
    /// the guardian's OWN expected old/new DIDs, HTTPS audience and nonce before
    /// using this guardian's local private key to approve those exact bytes.
    /// Cryptographic approval is not proof of the guardian's human/organization
    /// authorization; the caller must obtain that separately.
    /// </summary>
    public static bool TryCreateGuardianApproval(string successorSignature,
        string expectedPreviousIssuerDid, string expectedSuccessorIssuerDid,
        string guardianDid, byte[] guardianSeed, Uri expectedVerifierAudience,
        string expectedNonce, DateTimeOffset now, out string approval)
    {
        ArgumentNullException.ThrowIfNull(successorSignature);
        ArgumentNullException.ThrowIfNull(expectedPreviousIssuerDid);
        ArgumentNullException.ThrowIfNull(expectedSuccessorIssuerDid);
        ArgumentNullException.ThrowIfNull(guardianDid);
        ArgumentNullException.ThrowIfNull(guardianSeed);
        ArgumentNullException.ThrowIfNull(expectedVerifierAudience);
        ArgumentNullException.ThrowIfNull(expectedNonce);

        approval = string.Empty;
        if (!ValidAudience(expectedVerifierAudience) || !ValidNonce(expectedNonce) ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(expectedPreviousIssuerDid, out _) ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(expectedSuccessorIssuerDid, out byte[] successorPublicKey) ||
            !OfflineCredentialVerifier.TryDecodeDidKeyPublicKey(guardianDid, out byte[] guardianPublicKey) ||
            string.Equals(expectedPreviousIssuerDid, expectedSuccessorIssuerDid, StringComparison.Ordinal) ||
            string.Equals(guardianDid, expectedPreviousIssuerDid, StringComparison.Ordinal) ||
            string.Equals(guardianDid, expectedSuccessorIssuerDid, StringComparison.Ordinal) ||
            guardianSeed.Length != 32 || guardianSeed.All(static b => b == 0) ||
            !StrictJwtReader.TryRead(successorSignature, HeaderType, MaximumJwtLength,
                out JsonElement statement, KeyId(expectedSuccessorIssuerDid)) ||
            statement.EnumerateObject().Count() != 8 ||
            !Ed25519JwtSigner.VerifySignedJwt(successorSignature, successorPublicKey) ||
            !statement.TryGetProperty("version", out JsonElement version) ||
            version.ValueKind != JsonValueKind.Number || !version.TryGetInt32(out int v) || v != 1 ||
            !StrictJwtReader.TryGetString(statement, "purpose", out string purpose) ||
            !string.Equals(purpose, Purpose, StringComparison.Ordinal) ||
            !StrictJwtReader.TryGetString(statement, "previousIssuer", out string previous) ||
            !string.Equals(previous, expectedPreviousIssuerDid, StringComparison.Ordinal) ||
            !StrictJwtReader.TryGetString(statement, "successorIssuer", out string successor) ||
            !string.Equals(successor, expectedSuccessorIssuerDid, StringComparison.Ordinal) ||
            !StrictJwtReader.TryGetString(statement, "aud", out string audience) ||
            !string.Equals(audience, expectedVerifierAudience.AbsoluteUri, StringComparison.Ordinal) ||
            !StrictJwtReader.TryGetString(statement, "nonce", out string signedNonce) ||
            !string.Equals(signedNonce, expectedNonce, StringComparison.Ordinal) ||
            !PresentationChallengePolicy.TryGetNumericDate(statement, "iat", out decimal issued) ||
            !PresentationChallengePolicy.TryGetNumericDate(statement, "exp", out decimal expires))
        {
            return false;
        }

        decimal current = PresentationChallengePolicy.NumericDate(now);
        if (issued > current || expires <= current || expires <= issued ||
            expires - issued > LifetimeSeconds || expires - current > LifetimeSeconds)
        {
            return false;
        }

        try
        {
            // Extract only AFTER authenticating the original successor JWS.
            // Sign exactly its original payload, not a reserialized or partially
            // reconstructed claim set, so all approvals bind to the same bytes.
            string exactStatement = Ed25519JwtSigner.ExtractPayload(successorSignature);
            string signedApproval = Ed25519JwtSigner.CreateSignedJwt(
                Header(guardianDid), exactStatement, guardianSeed);
            if (signedApproval.Length > MaximumJwtLength ||
                !Ed25519JwtSigner.VerifySignedJwt(signedApproval, guardianPublicKey))
            {
                return false;
            }

            approval = signedApproval;
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    /// <summary>
    /// Assemble independent signed artefacts without collecting any signer seed.
    /// This does not establish a quorum: the relying party MUST invoke the
    /// existing IssuerGuardianRecovery.TryVerify with its independently pinned
    /// guardian policy, then atomically consume its one-use nonce.
    /// </summary>
    public static string AssembleEvidence(string successorSignature,
        IReadOnlyCollection<string> guardianApprovals)
    {
        ArgumentNullException.ThrowIfNull(successorSignature);
        ArgumentNullException.ThrowIfNull(guardianApprovals);

        if (!StrictJwtReader.IsCanonicalCompact(successorSignature, MaximumJwtLength) ||
            guardianApprovals.Count is < 2 or > 5 ||
            guardianApprovals.Any(static jwt => jwt is null ||
                !StrictJwtReader.IsCanonicalCompact(jwt, MaximumJwtLength)))
        {
            throw new ArgumentException("A compact successor JWS and two to five compact guardian JWS approvals are required.");
        }

        string evidence = JsonSerializer.Serialize(new
        {
            successorSignature,
            guardianSignatures = guardianApprovals
        });
        if (evidence.Length > MaximumEvidenceLength)
        {
            throw new ArgumentException("Recovery evidence exceeds the supported size.", nameof(guardianApprovals));
        }

        return evidence;
    }

    private static string Header(string did) =>
        JsonSerializer.Serialize(new { alg = "EdDSA", typ = HeaderType, kid = KeyId(did) });

    private static string KeyId(string did) => did + "#" + did["did:key:".Length..];

    private static bool ValidAudience(Uri uri) =>
        uri.IsAbsoluteUri && uri.Scheme == Uri.UriSchemeHttps &&
        uri.Host.Length != 0 && uri.UserInfo.Length == 0 &&
        uri.Fragment.Length == 0 && uri.AbsoluteUri.Length <= 2_048;

    private static bool ValidNonce(string nonce) =>
        nonce.Length is >= 20 and <= 128 &&
        nonce.All(static c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');
}
