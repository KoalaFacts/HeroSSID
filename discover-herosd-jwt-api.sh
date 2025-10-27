#!/bin/bash
set -e

echo "=========================================="
echo "HeroSD-JWT API Discovery Script"
echo "=========================================="
echo ""

# Check if dotnet is installed
if ! command -v dotnet &> /dev/null; then
    echo "Error: dotnet SDK is not installed"
    exit 1
fi

echo "Step 1: Finding latest HeroSD-JWT version on NuGet.org..."
echo ""

# Try to search for the package
dotnet nuget search HeroSD-JWT || echo "Search not available, will use latest"
echo ""

echo "Step 2: Creating temporary project to inspect HeroSD-JWT..."
echo ""

# Create temp directory
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"

# Create a temporary console project
dotnet new console -n ApiDiscovery
cd ApiDiscovery

# Add the HeroSD-JWT package
echo "Adding HeroSD-JWT package..."
dotnet add package HeroSD-JWT

# Get the actual version that was installed
INSTALLED_VERSION=$(dotnet list package | grep HeroSD-JWT | awk '{print $3}')
echo ""
echo "✓ Installed Version: $INSTALLED_VERSION"
echo ""

# Create a discovery program
cat > Program.cs << 'CSHARP'
using System;
using System.Reflection;
using System.Linq;

Console.WriteLine("=== HeroSD-JWT API Discovery ===\n");

// Discover all types in HeroSD-JWT assembly
var assembly = AppDomain.CurrentDomain.GetAssemblies()
    .FirstOrDefault(a => a.GetName().Name?.Contains("HeroSD") == true
                      || a.GetName().Name?.Contains("HeroSdJwt") == true);

if (assembly == null)
{
    Console.WriteLine("ERROR: HeroSD-JWT assembly not found!");
    Console.WriteLine("Available assemblies:");
    foreach (var asm in AppDomain.CurrentDomain.GetAssemblies())
    {
        Console.WriteLine($"  - {asm.GetName().Name}");
    }
    return;
}

Console.WriteLine($"Found Assembly: {assembly.GetName().Name} v{assembly.GetName().Version}\n");

// Get all public types
var types = assembly.GetTypes()
    .Where(t => t.IsPublic)
    .OrderBy(t => t.Namespace)
    .ThenBy(t => t.Name);

var groupedTypes = types.GroupBy(t => t.Namespace);

foreach (var group in groupedTypes)
{
    Console.WriteLine($"\n=== Namespace: {group.Key} ===\n");

    foreach (var type in group)
    {
        Console.WriteLine($"  {type.Name} ({(type.IsClass ? "class" : type.IsInterface ? "interface" : "struct")})");

        // Show public methods
        var methods = type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly)
            .Where(m => !m.IsSpecialName); // Exclude property getters/setters

        if (methods.Any())
        {
            Console.WriteLine("    Methods:");
            foreach (var method in methods)
            {
                var parameters = string.Join(", ", method.GetParameters().Select(p => $"{p.ParameterType.Name} {p.Name}"));
                Console.WriteLine($"      - {method.ReturnType.Name} {method.Name}({parameters})");
            }
        }

        // Show public properties
        var properties = type.GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly);

        if (properties.Any())
        {
            Console.WriteLine("    Properties:");
            foreach (var prop in properties)
            {
                var access = "";
                if (prop.CanRead && prop.CanWrite) access = "get; set;";
                else if (prop.CanRead) access = "get;";
                else if (prop.CanWrite) access = "set;";

                Console.WriteLine($"      - {prop.PropertyType.Name} {prop.Name} {{ {access} }}");
            }
        }

        Console.WriteLine();
    }
}

Console.WriteLine("\n=== Looking for SdJwtBuilder ===");
var builderType = assembly.GetTypes().FirstOrDefault(t => t.Name.Contains("Builder"));
if (builderType != null)
{
    Console.WriteLine($"\nFound: {builderType.FullName}");
    Console.WriteLine("\nStatic Methods:");
    foreach (var method in builderType.GetMethods(BindingFlags.Public | BindingFlags.Static))
    {
        if (!method.IsSpecialName)
        {
            var parameters = string.Join(", ", method.GetParameters().Select(p => $"{p.ParameterType.Name} {p.Name}"));
            Console.WriteLine($"  {method.ReturnType.Name} {method.Name}({parameters})");
        }
    }
}

Console.WriteLine("\n=== Looking for Signing Methods ===");
var allMethods = assembly.GetTypes()
    .SelectMany(t => t.GetMethods(BindingFlags.Public | BindingFlags.Instance))
    .Where(m => m.Name.Contains("Sign") && !m.IsSpecialName)
    .DistinctBy(m => m.Name);

foreach (var method in allMethods)
{
    var parameters = string.Join(", ", method.GetParameters().Select(p => $"{p.ParameterType.Name} {p.Name}"));
    Console.WriteLine($"  {method.DeclaringType?.Name}.{method.Name}({parameters}) -> {method.ReturnType.Name}");
}

Console.WriteLine("\n=== Discovery Complete ===");
CSHARP

# Build and run the discovery
echo "Step 3: Running API discovery..."
echo ""
dotnet run

# Clean up
cd /
rm -rf "$TEMP_DIR"

echo ""
echo "=========================================="
echo "Discovery Complete!"
echo "=========================================="
echo ""
echo "Save this output and use it to update:"
echo "  - src/Libraries/HeroSSID.Credentials/Implementations/HeroSdJwtGenerator.cs"
echo "  - src/Libraries/HeroSSID.Credentials/Implementations/HeroSdJwtVerifier.cs"
echo ""
echo "Update the package version in HeroSSID.Credentials.csproj to: $INSTALLED_VERSION"
