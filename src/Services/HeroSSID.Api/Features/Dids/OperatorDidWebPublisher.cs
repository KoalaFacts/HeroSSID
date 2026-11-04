using HeroSSID.DidOperations.DidMethods;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;

namespace HeroSSID.Api.Features.Dids;

/// <summary>
/// Operator-controlled, opt-in root did:web HTTPS document publication.
/// Only a public key is configured; no tenant, private key, trust grant,
/// identity verification or signing capability is exposed by this endpoint.
/// </summary>
public sealed class OperatorDidWebPublisher
{
    private const string PublicationSection = "DidWebPublication";
    private const string DocumentMediaType = "application/did+ld+json";
    private readonly string? _hostname;

    /// <summary>
    /// Validates publication policy eagerly. Absent configuration disables
    /// the endpoint; partially configured or unexpected policy fails startup.
    /// </summary>
    public OperatorDidWebPublisher(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        IConfigurationSection section = configuration.GetSection(PublicationSection);
        IConfigurationSection[] fields = [.. section.GetChildren()];
        if (fields.Length == 0 && section.Value is null)
        {
            return;
        }

        if (section.Value is not null || fields.Length != 2 ||
            fields.Any(static field =>
                field.Value is null || field.GetChildren().Any() ||
                field.Key is not ("Domain" or "PublicKeyHex")))
        {
            throw new InvalidOperationException(
                "Invalid operator-owned did:web publication configuration.");
        }

        string? domain = section["Domain"];
        string? keyHex = section["PublicKeyHex"];
        if (string.IsNullOrWhiteSpace(domain) ||
            keyHex is not { Length: 64 } ||
            !keyHex.All(static character =>
                character is >= '0' and <= '9' or >= 'a' and <= 'f') ||
            keyHex.All(static character => character == '0'))
        {
            throw new InvalidOperationException(
                "A canonical domain and nonzero 32-byte public Ed25519 key are required.");
        }

        byte[] publicKey = Convert.FromHexString(keyHex);
        try
        {
            var method = new DidWebMethod();
            Did = method.GenerateDidIdentifier(publicKey,
                new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["domain"] = domain
                });
            Document = method.CreateDidDocument(Did, publicKey);
            _hostname = domain;
        }
        catch (ArgumentException exception)
        {
            throw new InvalidOperationException(
                "The configured did:web domain or public key is invalid.",
                exception);
        }
    }

    /// <summary>Whether a valid operator-supplied publication is configured.</summary>
    public bool IsEnabled => Did is not null;

    /// <summary>The fixed DID being published, not an issuer trust enrollment.</summary>
    public string? Did { get; }

    /// <summary>Public JSON-LD document, never a private key or authorization token.</summary>
    public string? Document { get; }

    /// <summary>
    /// Serve the fixed DID document only to the configured HTTPS host. The
    /// deployment must independently control DNS/TLS and trusted proxy headers.
    /// Do not cache across key retirement without the operator's own policy.
    /// </summary>
    public IResult Handle(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!IsEnabled ||
            !string.Equals(context.Request.Scheme, Uri.UriSchemeHttps,
                StringComparison.Ordinal) ||
            !string.Equals(context.Request.Host.Host, _hostname,
                StringComparison.Ordinal) ||
            context.Request.Host.Port is not (null or 443))
        {
            return Results.NotFound();
        }

        context.Response.Headers.CacheControl = "no-store";
        return Results.Text(Document, DocumentMediaType);
    }

    /// <summary>
    /// Map only a root-domain DID publication. Path-based did:web identifiers,
    /// dynamic request-selected DIDs and tenant/private-key reads are excluded.
    /// </summary>
    public static void Map(IEndpointRouteBuilder app, OperatorDidWebPublisher publisher)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentNullException.ThrowIfNull(publisher);
        if (publisher.IsEnabled)
        {
            app.MapGet("/.well-known/did.json", publisher.Handle)
                .WithName("GetOperatorDidWebDocument")
                .ExcludeFromDescription();
        }
    }
}
