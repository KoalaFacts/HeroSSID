using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.VerifiablePresentations;
using NSec.Cryptography;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// End-to-end real issuer/holder Ed25519 keys and independently enrolled pins.
/// The injected HTTP probe is not an independent Wallet interoperability test.
/// </summary>
public sealed class JwtVcJsonPinnedDidWebWalletOnlinePreflightTests
{
    private const string IssuerDid = "did:web:issuer.example:members";
    private const string Method = IssuerDid + "#key-2";
    private const string IssuerName = "Example Membership Office";
    private const string CredentialType = "MembershipCredential";
    private static readonly Uri Context = new("https://issuer.example/contexts/membership/v1");
    private static readonly Uri CredentialId = new("https://issuer.example/credentials/membership-42");
    private static readonly Uri StatusUri = new("https://issuer.example/status/member-42.jwt");

    [Fact]
    public async Task GenuineIssuerStatusPreparesFullDisclosureAndHolderCanSignAfterConsent()
    {
        Fixture f = CreateFixture();
        string status = SignStatus(f, revoked: false);
        using var handler = new Probe(_ => Response(status));
        using var http = new HttpClient(handler);
        var preview = await Prepare(f, http);
        Assert.NotNull(preview);
        Assert.Equal(status, preview.SignedStatusJwt);
        Assert.Equal("member", preview.Disclosure.Disclosure.VerifiedSubject
            .GetProperty("role").GetString());
        Assert.Equal(1, handler.Calls);

        // The SDK cannot prove human consent; this call represents the Wallet
        // application's separate informed-consent boundary.
        string vp = JwtVcJsonPinnedDidWebWalletOnlinePreflight.CreateAfterPreview(
            preview, f.Challenge, f.CredentialJwt, f.IssuerPublicKey, [],
            f.HolderSeed, f.Clock);
        var first = JwtVcJsonPinnedDidWebIssuerAdmission.Check(
            vp, status, f.Tenant, f.Challenge.Audience, f.Challenge.Nonce,
            IssuerDid, Method, f.IssuerPublicKey, IssuerName, CredentialId,
            CredentialType, Context, [], f.Challenges, f.Clock,
            out JsonElement subject);
        Assert.Equal(JwtVcJsonPinnedDidWebIssuerAdmissionResult.SignedNotRevoked, first);
        Assert.Equal("member", subject.GetProperty("role").GetString());
        Assert.Equal(JwtVcJsonPinnedDidWebIssuerAdmissionResult.Invalid,
            JwtVcJsonPinnedDidWebIssuerAdmission.Check(
                vp, status, f.Tenant, f.Challenge.Audience, f.Challenge.Nonce,
                IssuerDid, Method, f.IssuerPublicKey, IssuerName, CredentialId,
                CredentialType, Context, [], f.Challenges, f.Clock, out _));
    }

    [Fact]
    public async Task RevokedOrForgedStatusNeverPreparesAnyClaims()
    {
        Fixture f = CreateFixture();
        bool revoked = true;
        using var handler = new Probe(_ => Response(
            revoked ? SignStatus(f, revoked: true) : "not.a.signed.jwt"));
        using var http = new HttpClient(handler);
        Assert.Null(await Prepare(f, http));
        revoked = false;
        Assert.Null(await Prepare(f, http));
        Assert.Equal(2, handler.Calls);
        Assert.True(f.Challenge.ExpiresAt > f.Clock.GetUtcNow());
    }

    [Fact]
    public async Task MismatchedSignedIssuerPolicyAndExpiredChallengeNeverContactIssuer()
    {
        Fixture f = CreateFixture();
        using var handler = new Probe(_ => Response(SignStatus(f, revoked: false)));
        using var http = new HttpClient(handler);
        Assert.Null(await Prepare(f, http, expectedIssuerName: "Wrong legal name"));
        Assert.Null(await Prepare(f, http, expectedCredentialId:
            new Uri("https://issuer.example/credentials/unrelated")));
        Assert.Null(await Prepare(f, http, expectedCredentialType: "OtherType"));
        Assert.Null(await Prepare(f, http, expectedSubjectContextUri:
            new Uri("https://issuer.example/contexts/wrong")));
        Assert.Null(await Prepare(f, http, expectedHolderDid: Identity().Did));
        Assert.Null(await Prepare(f, http, challenge: f.Challenge with
            { ExpiresAt = f.Clock.GetUtcNow().AddSeconds(-1) }));
        Assert.Equal(0, handler.Calls);
        Assert.NotNull(await Prepare(f, http));
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task LocalDenylistAndForeignIssuerKeyFailBeforeNetwork()
    {
        Fixture f = CreateFixture();
        string digest = Convert.ToHexStringLower(
            SHA256.HashData(Encoding.UTF8.GetBytes(f.CredentialJwt)));
        using var handler = new Probe(_ => Response(SignStatus(f, revoked: false)));
        using var http = new HttpClient(handler);
        Assert.Null(await Prepare(f, http, denied: [digest]));
        Assert.Null(await Prepare(f, http, denied: ["INVALID-DIGEST"]));
        Assert.Null(await Prepare(f, http, denied: [digest, digest]));
        Assert.Null(await Prepare(f, http, issuerKey: Identity().PublicKey));
        Assert.Equal(0, handler.Calls);
        Assert.NotNull(await Prepare(f, http));
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task ConsentProofRejectsChangedPolicyOrCredentialAndCannotSignWithForeignSeed()
    {
        Fixture f = CreateFixture();
        string status = SignStatus(f, revoked: false);
        using var handler = new Probe(_ => Response(status));
        using var http = new HttpClient(handler);
        var preview = await Prepare(f, http);
        Assert.NotNull(preview);
        string digest = Convert.ToHexStringLower(
            SHA256.HashData(Encoding.UTF8.GetBytes(f.CredentialJwt)));
        Assert.Throws<ArgumentException>(() =>
            JwtVcJsonPinnedDidWebWalletOnlinePreflight.CreateAfterPreview(
                preview, f.Challenge, f.CredentialJwt, f.IssuerPublicKey,
                [digest], f.HolderSeed, f.Clock));
        Assert.Throws<ArgumentException>(() =>
            JwtVcJsonPinnedDidWebWalletOnlinePreflight.CreateAfterPreview(
                preview, f.Challenge, "not.a.real.jwt", f.IssuerPublicKey,
                [], f.HolderSeed, f.Clock));
        Assert.Throws<ArgumentException>(() =>
            JwtVcJsonPinnedDidWebWalletOnlinePreflight.CreateAfterPreview(
                preview, f.Challenge, f.CredentialJwt, f.IssuerPublicKey,
                [], Identity().Seed, f.Clock));
    }

    private static Task<JwtVcJsonPinnedDidWebOnlineWalletPreview?> Prepare(
        Fixture f, HttpClient http, IReadOnlyCollection<string>? denied = null,
        byte[]? issuerKey = null, string? expectedIssuerName = null,
        Uri? expectedCredentialId = null, string? expectedCredentialType = null,
        Uri? expectedSubjectContextUri = null, string? expectedHolderDid = null,
        PresentationChallenge? challenge = null) =>
        JwtVcJsonPinnedDidWebWalletOnlinePreflight.TryPrepareAsync(
            StatusUri, http, challenge ?? f.Challenge, f.CredentialJwt,
            IssuerDid, Method, issuerKey ?? f.IssuerPublicKey,
            expectedIssuerName ?? IssuerName, expectedCredentialId ?? CredentialId,
            expectedCredentialType ?? CredentialType,
            expectedSubjectContextUri ?? Context, expectedHolderDid ?? f.HolderDid,
            denied ?? [], f.Clock);

    private static string SignStatus(Fixture f, bool revoked) =>
        JwtVcJsonPinnedDidWebIssuerStatus.Create(f.CredentialJwt,
            IssuerDid, Method, f.IssuerPublicKey, f.IssuerSeed,
            revoked, f.Clock.GetUtcNow(), f.Clock);

    private static HttpResponseMessage Response(string status)
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(status, Encoding.ASCII)
        };
        response.Content.Headers.ContentType =
            new MediaTypeHeaderValue("application/jwt");
        return response;
    }

    private sealed class Probe(Func<HttpRequestMessage, HttpResponseMessage> reply)
        : HttpMessageHandler
    {
        public int Calls { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            var response = reply(request);
            response.RequestMessage ??= request;
            return Task.FromResult(response);
        }
    }

    private static Fixture CreateFixture()
    {
        var issuer = Identity();
        var holder = Identity();
        var verifier = Identity();
        TimeProvider clock = TimeProvider.System;
        Guid tenant = Guid.NewGuid();
        var challenges = new InMemoryPresentationChallengeStore(clock);
        var challenge = challenges.Issue(
            tenant, "decentralized_identifier:" + verifier.Did, IssuerDid);
        using var subject = JsonDocument.Parse(
            JsonSerializer.Serialize(new { id = holder.Did, role = "member" }));
        DateTimeOffset now = clock.GetUtcNow();
        string jwt = JwtVcJsonPinnedDidWebIssuerCredential.CreateWithIssuerNameAndId(
            IssuerDid, Method, issuer.PublicKey, holder.Did,
            CredentialType, Context, subject.RootElement,
            issuer.Seed, now.AddMinutes(-1), now.AddMinutes(4),
            IssuerName, CredentialId);
        return new Fixture(jwt, challenge, tenant, issuer.Seed,
            issuer.PublicKey, holder.Seed, holder.Did, challenges, clock);
    }

    private static (byte[] Seed, byte[] PublicKey, string Did) Identity()
    {
        using Key key = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        byte[] publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        byte[] multicodec = new byte[34];
        multicodec[0] = 0xed;
        multicodec[1] = 0x01;
        publicKey.CopyTo(multicodec, 2);
        return (key.Export(KeyBlobFormat.RawPrivateKey), publicKey,
            "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(multicodec));
    }

    private sealed record Fixture(
        string CredentialJwt, PresentationChallenge Challenge, Guid Tenant,
        byte[] IssuerSeed, byte[] IssuerPublicKey,
        byte[] HolderSeed, string HolderDid,
        IPresentationChallengeStore Challenges, TimeProvider Clock);
}
