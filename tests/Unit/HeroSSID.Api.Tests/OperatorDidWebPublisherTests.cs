using HeroSSID.Data;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using System.Net;
using System.Text;
using HeroSSID.Api.Features.Dids;
using HeroSSID.DidOperations.DidMethods;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using NSec.Cryptography;

namespace HeroSSID.Api.Tests;

public sealed class OperatorDidWebPublisherTests
{
    [Fact]
    public void PublicationDisabledUnlessOperatorEnrollsExactPublicKey()
    {
        var disabled = NewPublisher([]);
        Assert.False(disabled.IsEnabled);
        Assert.Null(disabled.Did);
        Assert.Null(disabled.Document);

        using var key = Key.Create(SignatureAlgorithm.Ed25519);
        byte[] publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var enabled = NewPublisher(Entries(publicKey));
        Assert.True(enabled.IsEnabled);
        Assert.Equal("did:web:issuer.example", enabled.Did);
        Assert.NotNull(enabled.Document);
        Assert.True(DidWebPublishedKeyMatch.MatchesExpectedDocument(
            enabled.Did!, publicKey, enabled.Document));
        Assert.Equal("https://issuer.example/.well-known/did.json",
            DidWebMethod.GetDocumentUri(enabled.Did!).AbsoluteUri);
    }

    [Fact]
    public void MissingUnknownNoncanonicalAndZeroPublicKeyConfigurationsFailClosed()
    {
        using var key = Key.Create(SignatureAlgorithm.Ed25519);
        var entries = Entries(key.PublicKey.Export(KeyBlobFormat.RawPublicKey));

        var unexpected = new Dictionary<string, string?>(entries)
        {
            ["DidWebPublication:NewTrust"] = "any"
        };
        Assert.Throws<InvalidOperationException>(() => NewPublisher(unexpected));

        var missing = new Dictionary<string, string?>(entries);
        missing.Remove("DidWebPublication:PublicKeyHex");
        Assert.Throws<InvalidOperationException>(() => NewPublisher(missing));

        var badDomain = new Dictionary<string, string?>(entries)
        {
            ["DidWebPublication:Domain"] = "Issuer.Example"
        };
        Assert.Throws<InvalidOperationException>(() => NewPublisher(badDomain));

        var zero = new Dictionary<string, string?>(entries)
        {
            ["DidWebPublication:PublicKeyHex"] = new string('0', 64)
        };
        Assert.Throws<InvalidOperationException>(() => NewPublisher(zero));
    }

    [Fact]
    public void ExplicitSuccessorPinPublishesTheExactTwoKeyOverlapDocument()
    {
        using var oldKey = Key.Create(SignatureAlgorithm.Ed25519);
        using var successor = Key.Create(SignatureAlgorithm.Ed25519);
        byte[] oldPublicKey = oldKey.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        byte[] successorPublicKey = successor.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var entries = Entries(oldPublicKey);
        entries.Add("DidWebPublication:SuccessorPublicKeyHex",
            Convert.ToHexStringLower(successorPublicKey));

        var publisher = NewPublisher(entries);
        Assert.True(publisher.IsEnabled);
        Assert.Equal("did:web:issuer.example", publisher.Did);
        Assert.NotNull(publisher.Document);
        Assert.True(DidWebPinnedKeyTransition.MatchesExpectedTransitionDocument(
            publisher.Did!, oldPublicKey, successorPublicKey, publisher.Document));
        Assert.False(DidWebPublishedKeyMatch.MatchesExpectedDocument(
            publisher.Did!, oldPublicKey, publisher.Document));
    }

    [Fact]
    public async Task ExplicitTwoKeyOverlapIsServedOnThePinnedHttpsHostOnly()
    {
        using var oldKey = Key.Create(SignatureAlgorithm.Ed25519);
        using var successor = Key.Create(SignatureAlgorithm.Ed25519);
        byte[] oldPublicKey = oldKey.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        byte[] successorPublicKey = successor.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        using var hosting = new DidWebHttpFactory(oldPublicKey, successorPublicKey);
        using var client = hosting.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        using var response = await client.GetAsync(
            new Uri("https://issuer.example/.well-known/did.json", UriKind.Absolute))
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        string json = await response.Content.ReadAsStringAsync().ConfigureAwait(true);
        Assert.True(DidWebPinnedKeyTransition.MatchesExpectedTransitionDocument(
            "did:web:issuer.example", oldPublicKey, successorPublicKey, json));

        using var wrongHost = await client.GetAsync(
            new Uri("https://unapproved.example/.well-known/did.json", UriKind.Absolute))
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NotFound, wrongHost.StatusCode);
        using var wrongPort = await client.GetAsync(
            new Uri("https://issuer.example:8443/.well-known/did.json", UriKind.Absolute))
            .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NotFound, wrongPort.StatusCode);
    }

    [Fact]
    public void TwoKeyOverlapRefusesMissingInvalidOrIdenticalSuccessorPins()
    {
        using var oldKey = Key.Create(SignatureAlgorithm.Ed25519);
        using var successor = Key.Create(SignatureAlgorithm.Ed25519);
        byte[] oldPublicKey = oldKey.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        byte[] successorPublicKey = successor.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var entries = Entries(oldPublicKey);
        entries.Add("DidWebPublication:SuccessorPublicKeyHex",
            Convert.ToHexStringLower(successorPublicKey));
        Assert.True(NewPublisher(entries).IsEnabled);

        foreach (string invalid in new[]
        {
            Convert.ToHexStringLower(oldPublicKey),
            new string('0', 64),
            Convert.ToHexString(successorPublicKey),
            "not-a-public-key"
        })
        {
            var invalidEntries = new Dictionary<string, string?>(entries)
            {
                ["DidWebPublication:SuccessorPublicKeyHex"] = invalid
            };
            Assert.Throws<InvalidOperationException>(() => NewPublisher(invalidEntries));
        }

        var unexpected = new Dictionary<string, string?>(entries)
        {
            ["DidWebPublication:EnableAutomaticTrust"] = "true"
        };
        Assert.Throws<InvalidOperationException>(() => NewPublisher(unexpected));
    }

    [Fact]
    public async Task HttpsExactHostServesDocumentButWrongHostSchemeOrPortDoesNot()
    {
        using var key = Key.Create(SignatureAlgorithm.Ed25519);
        var enabled = NewPublisher(Entries(key.PublicKey.Export(KeyBlobFormat.RawPublicKey)));

        using var services = new ServiceCollection().AddLogging().BuildServiceProvider();
        DefaultHttpContext valid = Context("https", "issuer.example");
        valid.RequestServices = services;
        await enabled.Handle(valid).ExecuteAsync(valid).ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status200OK, valid.Response.StatusCode);
        Assert.Equal("application/did+ld+json", valid.Response.ContentType);
        Assert.Equal("no-store", valid.Response.Headers.CacheControl.ToString());
        valid.Response.Body.Position = 0;
        using var reader = new StreamReader(valid.Response.Body, Encoding.UTF8);
        Assert.Equal(enabled.Document, await reader.ReadToEndAsync().ConfigureAwait(true));

        foreach (var pair in new[]
        {
            ("http", "issuer.example"),
            ("https", "other.example"),
            ("https", "issuer.example:8443"),
            ("https", "issuer.example:9999999999")
        })
        {
            DefaultHttpContext denied = Context(pair.Item1, pair.Item2);
            denied.RequestServices = services;
            await enabled.Handle(denied).ExecuteAsync(denied).ConfigureAwait(true);
            Assert.Equal(StatusCodes.Status404NotFound, denied.Response.StatusCode);
            Assert.Equal(0, denied.Response.Body.Length);
        }
    }

    [Fact]
    public async Task ActualAnonymousRouteServesOnlyTheExplicitlyEnrolledDomain()
    {
        using var key = Key.Create(SignatureAlgorithm.Ed25519);
        byte[] publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        using var hosting = new DidWebHttpFactory(publicKey);
        using var client = hosting.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        using var good = await client.GetAsync(
            new Uri("https://issuer.example/.well-known/did.json", UriKind.Absolute)).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, good.StatusCode);
        Assert.Equal("application/did+ld+json", good.Content.Headers.ContentType?.MediaType);
        Assert.Equal("no-store", good.Headers.CacheControl?.ToString());
        string json = await good.Content.ReadAsStringAsync().ConfigureAwait(true);
        Assert.True(DidWebPublishedKeyMatch.MatchesExpectedDocument(
            "did:web:issuer.example", publicKey, json));

        using var wrongHost = await client.GetAsync(
            new Uri("https://unapproved.example/.well-known/did.json", UriKind.Absolute)).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NotFound, wrongHost.StatusCode);

        using var wrongPort = await client.GetAsync(
            new Uri("https://issuer.example:8443/.well-known/did.json", UriKind.Absolute)).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NotFound, wrongPort.StatusCode);
        // Overflowed Host ports must not be mistaken for no explicit port.
        // Direct-handler coverage above exercises malformed HostString; this
        // normal TestServer request exercises ordinary alternate ports.


        using var disabled = new DidWebHttpFactory(null);
        using var disabledClient = disabled.CreateClient();
        using var missing = await disabledClient.GetAsync(
            new Uri("https://issuer.example/.well-known/did.json", UriKind.Absolute)).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NotFound, missing.StatusCode);
    }


    [Fact]
    public void ExplicitRetirementPublishesSuccessorOnlyWithoutChangingTheDidOrKey2Fragment()
    {
        using var oldKey = Key.Create(SignatureAlgorithm.Ed25519);
        using var nextKey = Key.Create(SignatureAlgorithm.Ed25519);
        byte[] oldPublicKey = oldKey.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        byte[] nextPublicKey = nextKey.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var entries = Entries(oldPublicKey);
        entries.Add("DidWebPublication:SuccessorPublicKeyHex",
            Convert.ToHexStringLower(nextPublicKey));
        entries.Add("DidWebPublication:RetireOldKey", "true");

        var publisher = NewPublisher(entries);
        Assert.Equal("did:web:issuer.example", publisher.Did);
        Assert.NotNull(publisher.Document);
        Assert.True(DidWebPinnedKeyRetirement.MatchesExpectedRetirementDocument(
            publisher.Did!, oldPublicKey, nextPublicKey, publisher.Document));
        Assert.False(DidWebPinnedKeyTransition.MatchesExpectedTransitionDocument(
            publisher.Did!, oldPublicKey, nextPublicKey, publisher.Document));
        Assert.False(DidWebPublishedKeyMatch.MatchesExpectedDocument(
            publisher.Did!, oldPublicKey, publisher.Document));
    }

    [Fact]
    public async Task RetiredDocumentIsServedOnlyOnThePinnedHttpsHost()
    {
        using var oldKey = Key.Create(SignatureAlgorithm.Ed25519);
        using var nextKey = Key.Create(SignatureAlgorithm.Ed25519);
        byte[] oldPublicKey = oldKey.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        byte[] nextPublicKey = nextKey.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var entries = Entries(oldPublicKey);
        entries.Add("DidWebPublication:SuccessorPublicKeyHex",
            Convert.ToHexStringLower(nextPublicKey));
        entries.Add("DidWebPublication:RetireOldKey", "true");
        var publisher = NewPublisher(entries);
        using var services = new ServiceCollection().AddLogging().BuildServiceProvider();

        DefaultHttpContext valid = Context("https", "issuer.example");
        valid.RequestServices = services;
        await publisher.Handle(valid).ExecuteAsync(valid).ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status200OK, valid.Response.StatusCode);
        Assert.Equal("no-store", valid.Response.Headers.CacheControl.ToString());
        valid.Response.Body.Position = 0;
        using var reader = new StreamReader(valid.Response.Body, Encoding.UTF8);
        string document = await reader.ReadToEndAsync().ConfigureAwait(true);
        Assert.True(DidWebPinnedKeyRetirement.MatchesExpectedRetirementDocument(
            "did:web:issuer.example", oldPublicKey, nextPublicKey, document));

        foreach (var pair in new[]
        {
            ("http", "issuer.example"),
            ("https", "other.example"),
            ("https", "issuer.example:8443"),
            ("https", "issuer.example:9999999999")
        })
        {
            DefaultHttpContext denied = Context(pair.Item1, pair.Item2);
            denied.RequestServices = services;
            await publisher.Handle(denied).ExecuteAsync(denied).ConfigureAwait(true);
            Assert.Equal(StatusCodes.Status404NotFound, denied.Response.StatusCode);
            Assert.Equal(0, denied.Response.Body.Length);
        }
    }

    [Fact]
    public void RetirementRequiresExplicitTrueAndTwoDistinctPins()
    {
        using var oldKey = Key.Create(SignatureAlgorithm.Ed25519);
        using var nextKey = Key.Create(SignatureAlgorithm.Ed25519);
        byte[] oldPublicKey = oldKey.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var entries = Entries(oldPublicKey);
        entries.Add("DidWebPublication:SuccessorPublicKeyHex",
            Convert.ToHexStringLower(nextKey.PublicKey.Export(KeyBlobFormat.RawPublicKey)));
        entries.Add("DidWebPublication:RetireOldKey", "true");
        Assert.True(NewPublisher(entries).IsEnabled);

        foreach (string invalid in new[] { "false", "True", "1", "" })
        {
            var copy = new Dictionary<string, string?>(entries)
            {
                ["DidWebPublication:RetireOldKey"] = invalid
            };
            Assert.Throws<InvalidOperationException>(() => NewPublisher(copy));
        }

        var missingSuccessor = new Dictionary<string, string?>(entries);
        missingSuccessor.Remove("DidWebPublication:SuccessorPublicKeyHex");
        Assert.Throws<InvalidOperationException>(() => NewPublisher(missingSuccessor));

        var identical = new Dictionary<string, string?>(entries)
        {
            ["DidWebPublication:SuccessorPublicKeyHex"] =
                Convert.ToHexStringLower(oldPublicKey)
        };
        Assert.Throws<InvalidOperationException>(() => NewPublisher(identical));

        var unexpected = new Dictionary<string, string?>(entries)
        {
            ["DidWebPublication:GrantIssuerTrust"] = "true"
        };
        Assert.Throws<InvalidOperationException>(() => NewPublisher(unexpected));
    }

    private sealed class DidWebHttpFactory(byte[]? keyBytes, byte[]? successorKeyBytes = null) : WebApplicationFactory<Program>
    {
        private readonly string _database = Guid.NewGuid().ToString("N");

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Testing");
            builder.ConfigureAppConfiguration((_, configuration) =>
            {
                var entries = new Dictionary<string, string?>
                {
                    ["Jwt:Secret"] = "HTTP-regression-test-signing-key-with-at-least-32-bytes",
                    ["Jwt:Issuer"] = "https://http-test.example",
                    ["Jwt:Audience"] = "https://http-test.example",
                    ["ConnectionStrings:HeroDb"] = "Host=unused;Database=unused",
                    ["HEROSSID_DB_PASSWORD"] = "unused",
                    // Host-filtering is a separate middleware. Allow both test
                    // hosts so these assertions exercise the did:web publisher
                    // itself rather than the framework's AllowedHosts gate.
                    ["AllowedHosts"] = "localhost;issuer.example;unapproved.example"
                };
                if (keyBytes is not null)
                {
                    foreach (var entry in Entries(keyBytes))
                    {
                        entries.Add(entry.Key, entry.Value);
                    }
                    if (successorKeyBytes is not null)
                    {
                        entries.Add("DidWebPublication:SuccessorPublicKeyHex",
                            Convert.ToHexStringLower(successorKeyBytes));
                    }
                }

                configuration.AddInMemoryCollection(entries);
            });
            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<DbContextOptions<HeroDbContext>>();
                services.RemoveAll<IDbContextOptionsConfiguration<HeroDbContext>>();
                services.AddDbContext<HeroDbContext>(
                    options => options.UseInMemoryDatabase(_database));
                services.AddSingleton<IDataProtectionProvider>(
                    new EphemeralDataProtectionProvider());
            });
        }
    }

    private static OperatorDidWebPublisher NewPublisher(Dictionary<string, string?> values) =>
        new(new ConfigurationBuilder().AddInMemoryCollection(values).Build());

    private static Dictionary<string, string?> Entries(byte[] publicKey) => new()
    {
        ["DidWebPublication:Domain"] = "issuer.example",
        ["DidWebPublication:PublicKeyHex"] = Convert.ToHexStringLower(publicKey)
    };

    private static DefaultHttpContext Context(string scheme, string host)
    {
        var context = new DefaultHttpContext();
        context.Request.Scheme = scheme;
        context.Request.Host = new HostString(host);
        context.Response.Body = new MemoryStream();
        return context;
    }
}
