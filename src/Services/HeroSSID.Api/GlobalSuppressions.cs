using System.Diagnostics.CodeAnalysis;

// API project: DTOs must be public for JSON serialization and OpenAPI documentation
// CA1515: Consider making public types internal
[assembly: SuppressMessage("Design", "CA1515:Consider making public types internal",
    Justification = "DTOs must be public for JSON serialization and OpenAPI",
    Scope = "namespaceanddescendants",
    Target = "~N:HeroSSID.Api.Features")]

// API project: Simple logging pattern acceptable for MVP endpoints
// CA1848: Use LoggerMessage delegates for performance
[assembly: SuppressMessage("Performance", "CA1848:Use the LoggerMessage delegates",
    Justification = "Simple logging pattern appropriate for MVP",
    Scope = "namespaceanddescendants",
    Target = "~N:HeroSSID.Api.Features")]

[assembly: SuppressMessage("Performance", "CA1848:Use the LoggerMessage delegates",
    Justification = "Simple logging pattern appropriate for MVP",
    Scope = "namespaceanddescendants",
    Target = "~N:HeroSSID.Api.Data")]

// API project: ConfigureAwait not needed in ASP.NET Core
// CA2007: Consider calling ConfigureAwait on the awaited task
[assembly: SuppressMessage("Reliability", "CA2007:Consider calling ConfigureAwait on the awaited task",
    Justification = "ConfigureAwait(false) not needed in ASP.NET Core context",
    Scope = "namespaceanddescendants",
    Target = "~N:HeroSSID.Api.Features")]

[assembly: SuppressMessage("Reliability", "CA2007:Consider calling ConfigureAwait on the awaited task",
    Justification = "ConfigureAwait(false) not needed in ASP.NET Core context",
    Scope = "namespaceanddescendants",
    Target = "~N:HeroSSID.Api.Data")]
