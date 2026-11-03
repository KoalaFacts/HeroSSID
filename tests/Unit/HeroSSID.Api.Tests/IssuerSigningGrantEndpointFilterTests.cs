using System.Security.Claims;
using System.Text.Json;
using HeroSSID.Api.Features.Credentials;
using HeroSSID.Data;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using NSec.Cryptography;

namespace HeroSSID.Api.Tests;

public sealed class IssuerSigningGrantEndpointFilterTests
{
    [Fact]
    public void AllThreeIssuanceFormatsRequireTheSameExactIssuerGrant()
    {
        using var allowedKey = Key.Create(SignatureAlgorithm.Ed25519);
        using var deniedKey = Key.Create(SignatureAlgorithm.Ed25519);
        string allowedDid = DidFromKey(allowedKey);
        string deniedDid = DidFromKey(deniedKey);
        Guid tenant = HeroDbContext.DefaultTenantId;
        var config = new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?>
            {
                ["IssuerSigningGrants:EnforcedTenants:0"] = tenant.ToString("D"),
                ["IssuerSigningGrants:Grants:0:TenantId"] = tenant.ToString("D"),
                ["IssuerSigningGrants:Grants:0:ClientId"] = "test_client",
                ["IssuerSigningGrants:Grants:0:IssuerDid"] = allowedDid
            }).Build();
        using var services = new ServiceCollection()
            .AddSingleton(new IssuerSigningGrantRegistry(config)).BuildServiceProvider();
        var context = new DefaultHttpContext { RequestServices = services };
        context.User = Principal(tenant, "test_client");

        object[] allowed =
        [
            new IssueCredentialRequest { IssuerDid = allowedDid },
            new IssueJwtVcJsonCredentialRequest { IssuerDid = allowedDid },
            new IssueVcdm20CredentialRequest { IssuerDid = allowedDid }
        ];
        object[] denied =
        [
            new IssueCredentialRequest { IssuerDid = deniedDid },
            new IssueJwtVcJsonCredentialRequest { IssuerDid = deniedDid },
            new IssueVcdm20CredentialRequest { IssuerDid = deniedDid }
        ];

        foreach (object request in allowed)
        {
            Assert.True(IssuerSigningGrantEndpointFilter.Allows(context, request));
        }
        foreach (object request in denied)
        {
            Assert.False(IssuerSigningGrantEndpointFilter.Allows(context, request));
        }

        context.User = Principal(tenant, "ungranted_client");
        foreach (object request in allowed)
        {
            Assert.False(IssuerSigningGrantEndpointFilter.Allows(context, request));
        }

        context.User = Principal(Guid.NewGuid(), "test_client");
        foreach (object request in allowed)
        {
            Assert.True(IssuerSigningGrantEndpointFilter.Allows(context, request));
        }

        context.User = new ClaimsPrincipal(new ClaimsIdentity());
        Assert.False(IssuerSigningGrantEndpointFilter.Allows(context, allowed[0]));
        Assert.False(IssuerSigningGrantEndpointFilter.Allows(context, new object()));
    }

    [Fact]
    public void EveryIssuanceRouteRejectsAForbiddenTypeEvenWithApprovedIssuerDid()
    {
        using var key = Key.Create(SignatureAlgorithm.Ed25519);
        string did = DidFromKey(key);
        Guid tenant = HeroDbContext.DefaultTenantId;
        var config = new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?>
            {
                ["IssuerSigningGrants:EnforcedTenants:0"] = tenant.ToString("D"),
                ["IssuerSigningGrants:Grants:0:TenantId"] = tenant.ToString("D"),
                ["IssuerSigningGrants:Grants:0:ClientId"] = "test_client",
                ["IssuerSigningGrants:Grants:0:IssuerDid"] = did,
                ["IssuerSigningGrants:Grants:0:CredentialTypes:0"] = "MembershipCredential",
                ["IssuerSigningGrants:Grants:0:CredentialTypes:1"] =
                    "https://issuer.example/credentials#MembershipCredential"
            }).Build();
        using var services = new ServiceCollection()
            .AddSingleton(new IssuerSigningGrantRegistry(config)).BuildServiceProvider();
        var context = new DefaultHttpContext { RequestServices = services };
        context.User = Principal(tenant, "test_client");

        object[] forbidden =
        [
            new IssueCredentialRequest { IssuerDid = did, CredentialType = "AdministratorCredential" },
            new IssueJwtVcJsonCredentialRequest
            {
                IssuerDid = did,
                CredentialType = "https://issuer.example/credentials#AdministratorCredential"
            },
            new IssueVcdm20CredentialRequest { IssuerDid = did, CredentialType = "AdministratorCredential" }
        ];

        foreach (object request in forbidden)
        {
            Assert.False(IssuerSigningGrantEndpointFilter.Allows(context, request));
        }
    }

    [Fact]
    public void SubjectClaimGrantsRejectUnapprovedFieldsAcrossAllIssuanceFormats()
    {
        using var key = Key.Create(SignatureAlgorithm.Ed25519);
        string did = DidFromKey(key);
        Guid tenant = HeroDbContext.DefaultTenantId;
        var config = new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?>
            {
                ["IssuerSigningGrants:EnforcedTenants:0"] = tenant.ToString("D"),
                ["IssuerSigningGrants:Grants:0:TenantId"] = tenant.ToString("D"),
                ["IssuerSigningGrants:Grants:0:ClientId"] = "test_client",
                ["IssuerSigningGrants:Grants:0:IssuerDid"] = did,
                ["IssuerSigningGrants:Grants:0:SubjectClaimNames:0"] = "membership"
            }).Build();
        using var services = new ServiceCollection()
            .AddSingleton(new IssuerSigningGrantRegistry(config)).BuildServiceProvider();
        var context = new DefaultHttpContext { RequestServices = services };
        context.User = Principal(tenant, "test_client");

        object[] allowed =
        [
            new IssueCredentialRequest
            {
                IssuerDid = did,
                Claims = new Dictionary<string, object> { ["membership"] = "active" }
            },
            new IssueJwtVcJsonCredentialRequest
            {
                IssuerDid = did,
                CredentialSubject = JsonSerializer.SerializeToElement(
                    new { id = did, membership = "active" })
            },
            new IssueVcdm20CredentialRequest
            {
                IssuerDid = did,
                CredentialSubject = JsonSerializer.SerializeToElement(
                    new { id = did, membership = "active" })
            }
        ];
        object[] forbidden =
        [
            new IssueCredentialRequest
            {
                IssuerDid = did,
                Claims = new Dictionary<string, object>
                {
                    ["membership"] = "active", ["administrator"] = true
                }
            },
            new IssueJwtVcJsonCredentialRequest
            {
                IssuerDid = did,
                CredentialSubject = JsonSerializer.SerializeToElement(
                    new { id = did, membership = "active", administrator = true })
            },
            new IssueVcdm20CredentialRequest
            {
                IssuerDid = did,
                CredentialSubject = JsonSerializer.SerializeToElement(
                    new { id = did, membership = "active", administrator = true })
            }
        ];

        foreach (object request in allowed)
        {
            Assert.True(IssuerSigningGrantEndpointFilter.Allows(context, request));
        }

        foreach (object request in forbidden)
        {
            Assert.False(IssuerSigningGrantEndpointFilter.Allows(context, request));
        }
    }

    private static ClaimsPrincipal Principal(Guid tenant, string client) =>
        new(new ClaimsIdentity(
        [
            new Claim("tenant_id", tenant.ToString("D")),
            new Claim("client_id", client),
            new Claim("sub", client),
            new Claim("scope", "credential:issue")
        ], "verified-jwt"));

    private static string DidFromKey(Key key)
    {
        var bytes = new byte[34];
        bytes[0] = 0xed;
        bytes[1] = 0x01;
        key.PublicKey.Export(KeyBlobFormat.RawPublicKey).CopyTo(bytes, 2);
        return "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(bytes);
    }
}
