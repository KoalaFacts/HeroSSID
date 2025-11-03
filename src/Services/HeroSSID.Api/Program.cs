using HeroSSID.Data;
using HeroSSID.Data.Entities;
using HeroSSID.Cryptography;
using HeroSSID.Cryptography.Abstractions;
using HeroSSID.Core.TenantManagement;
using HeroSSID.Infrastructure.KeyEncryption;
using HeroSSID.Infrastructure.RateLimiting;
using HeroSSID.Infrastructure.TenantManagement;
using HeroSSID.DidOperations.DidMethod;
using HeroSSID.DidOperations.DidCreation;
using HeroSSID.DidOperations.DidResolution;
using HeroSSID.DidOperations.DidMethods;
using HeroSSID.Credentials.CredentialIssuance;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Api.Features.Dids;
using HeroSSID.Api.Features.Credentials;
using HeroSSID.Api.Features.OAuth;
using HeroSSID.Api.Data;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.EntityFrameworkCore;
using Asp.Versioning;
using Microsoft.AspNetCore.RateLimiting;
using System.Threading.RateLimiting;
using Scalar.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// Register core services
builder.Services.AddSingleton<ICryptographicCodeGenerator, CryptographicCodeGenerator>();

// Register key encryption service (required for DID operations)
builder.Services.AddScoped<IKeyEncryptionService, LocalKeyEncryptionService>();

// Register rate limiter for credential operations
builder.Services.AddSingleton<IRateLimiter, InMemoryRateLimiter>();

// Register tenant context (MVP: single tenant, production: replace with JWT-based implementation)
builder.Services.AddScoped<ITenantContext, DefaultTenantContext>();

// Register DID method implementations (did:key and did:web)
builder.Services.AddScoped<IDidMethod, DidKeyMethod>();
builder.Services.AddScoped<IDidMethod, DidWebMethod>();

// Register DID method resolver (required for DID resolution)
builder.Services.AddScoped<DidMethodResolver>();

// Register DID services
builder.Services.AddScoped<IDidCreationService, DidCreationService>();
builder.Services.AddScoped<IDidResolutionService, DidResolutionService>();

// Register Credential services
builder.Services.AddScoped<ICredentialIssuanceService, CredentialIssuanceService>();
builder.Services.AddScoped<ICredentialVerificationService, CredentialVerificationService>();

// Add database context
builder.Services.AddDbContext<HeroDbContext>(options =>
{
    var connectionString = builder.Configuration.GetConnectionString("HeroDb")
        ?? throw new InvalidOperationException("Connection string 'HeroDb' not found.");

    // Get password from environment variable for security
    var dbPassword = builder.Configuration["HEROSSID_DB_PASSWORD"]
        ?? Environment.GetEnvironmentVariable("HEROSSID_DB_PASSWORD")
        ?? (builder.Environment.IsDevelopment() ? "postgres" : null)
        ?? throw new InvalidOperationException("Database password not configured. Set HEROSSID_DB_PASSWORD environment variable.");

    connectionString += $";Password={dbPassword}";
    options.UseNpgsql(connectionString);
});

// Add API versioning (T028)
builder.Services.AddApiVersioning(options =>
{
    options.DefaultApiVersion = new ApiVersion(1, 0);
    options.AssumeDefaultVersionWhenUnspecified = true;
    options.ReportApiVersions = true;
    options.ApiVersionReader = new UrlSegmentApiVersionReader();
});

// Add OpenAPI/Swagger support (T026)
builder.Services.AddOpenApi();

// Add CORS (T025)
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        if (builder.Environment.IsDevelopment())
        {
            // Development: Use configured localhost origins for local development
            var allowedOrigins = builder.Configuration
                .GetSection("Cors:AllowedOrigins")
                .Get<string[]>() ?? ["http://localhost:3000", "http://localhost:5173"];

            policy.WithOrigins(allowedOrigins)
                  .AllowCredentials()
                  .AllowAnyMethod()
                  .AllowAnyHeader();
        }
        else
        {
            // Production: Require explicit CORS configuration
            var allowedOrigins = builder.Configuration
                .GetSection("Cors:AllowedOrigins")
                .Get<string[]>() ?? [];

            if (allowedOrigins.Length == 0)
            {
                throw new InvalidOperationException("CORS origins not configured for production. Set Cors:AllowedOrigins in appsettings.json");
            }

            policy.WithOrigins(allowedOrigins)
                  .AllowCredentials()
                  .WithMethods("GET", "POST", "PUT", "DELETE")
                  .WithHeaders("Content-Type", "Authorization");
        }
    });
});

// Add rate limiting (T031)
builder.Services.AddRateLimiter(options =>
{
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
    {
        // Use authenticated user if available, otherwise use IP address (not spoofable Host header)
        var partitionKey = httpContext.User.Identity?.Name
            ?? httpContext.Connection.RemoteIpAddress?.ToString()
            ?? "anonymous";

        return RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: partitionKey,
            factory: partition => new FixedWindowRateLimiterOptions
            {
                AutoReplenishment = true,
                PermitLimit = 100,
                Window = TimeSpan.FromMinutes(1)
            });
    });

    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
});

// Add problem details support (T029)
builder.Services.AddProblemDetails();

// Add structured logging (T030)
// Note: AddServiceDefaults() is an Aspire extension - skipping for now as it requires Aspire ServiceDefaults package

// Add JWT Bearer authentication for OAuth 2.0 (T066)
var jwtSecret = builder.Configuration["Jwt:Secret"] ?? "your-256-bit-secret-key-change-in-production-min-32-chars";
var jwtIssuer = builder.Configuration["Jwt:Issuer"] ?? "https://herossid.api";
var jwtAudience = builder.Configuration["Jwt:Audience"] ?? "https://herossid.api";

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtIssuer,
            ValidAudience = jwtAudience,
            IssuerSigningKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(jwtSecret)),
            ClockSkew = TimeSpan.FromMinutes(5)
        };
    });

builder.Services.AddAuthorizationBuilder()
    .AddPolicy("RequireAuthentication", policy => policy.RequireAuthenticatedUser());

// Configure HSTS (HIGH-2)
builder.Services.AddHsts(options =>
{
    options.IncludeSubDomains = true;
    options.MaxAge = TimeSpan.FromDays(365);
    options.Preload = true;
});

// Configure Kestrel request size limits (MEDIUM-6)
builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.MaxRequestBodySize = 10_485_760; // 10 MB limit
    options.Limits.MaxRequestLineSize = 8192; // 8 KB limit for request line
    options.Limits.MaxRequestHeadersTotalSize = 32768; // 32 KB limit for headers
});

var app = builder.Build();

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();

    // Add Scalar UI for API documentation (T027)
    app.MapScalarApiReference();
}

// Use HTTPS redirection (T025)
app.UseHttpsRedirection();

// Add HSTS for production (HIGH-2)
if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
}

// Add security headers (HIGH-1)
app.Use(async (context, next) =>
{
    context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Append("X-Frame-Options", "DENY");
    context.Response.Headers.Append("X-XSS-Protection", "1; mode=block");
    context.Response.Headers.Append("Referrer-Policy", "strict-origin-when-cross-origin");
    context.Response.Headers.Append("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
    context.Response.Headers.Append("Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';");
    await next(context).ConfigureAwait(false);
});

// Use CORS
app.UseCors();

// Use authentication and authorization (CRITICAL-2)
app.UseAuthentication();
app.UseAuthorization();

// Use rate limiting
app.UseRateLimiter();

// Use exception handling (T029)
// Use DeveloperExceptionPage in development, otherwise use exception handler
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler();
}
app.UseStatusCodePages();

// Health check endpoint
app.MapGet("/health", () => Results.Ok(new { status = "healthy", timestamp = DateTimeOffset.UtcNow }))
    .WithName("HealthCheck")
    .ExcludeFromDescription();

// Map User Story 1 endpoints
app.MapDidEndpoints();
app.MapCredentialEndpoints();

// Map OAuth 2.0 endpoints (T063)
app.MapTokenEndpoint();
app.MapOAuthMetadataEndpoint();

// Seed development data (T033)
if (app.Environment.IsDevelopment())
{
#pragma warning disable CA2007 // ConfigureAwait not needed in main method
    await DatabaseSeeder.SeedDevelopmentDataAsync(app.Services, app.Logger);
#pragma warning restore CA2007
}

#pragma warning disable CA1849 // Calling Run() is acceptable for main entry point
app.Run();
#pragma warning restore CA1849

// Make Program class accessible to integration/contract tests
#pragma warning disable CA1515 // Program class must be public for WebApplicationFactory testing
public partial class Program { }
#pragma warning restore CA1515
