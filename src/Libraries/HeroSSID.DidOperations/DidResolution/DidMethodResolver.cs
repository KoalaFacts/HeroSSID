using HeroSSID.DidOperations.DidMethod;

namespace HeroSSID.DidOperations.DidResolution;

/// <summary>
/// Resolves DID method implementations based on DID identifier.
/// Routes DID operations to the appropriate method implementation (did:key, did:web, etc.).
/// </summary>
public sealed class DidMethodResolver
{
    private readonly IReadOnlyDictionary<string, IDidMethod> _methodsByName;
    private readonly List<IDidMethod> _methods;

    /// <summary>
    /// Creates a new DidMethodResolver with the given method implementations.
    /// </summary>
    /// <param name="methods">Collection of DID method implementations</param>
    /// <exception cref="ArgumentNullException">Thrown if methods is null</exception>
    /// <exception cref="ArgumentException">Thrown if multiple methods have the same name</exception>
    public DidMethodResolver(IEnumerable<IDidMethod> methods)
    {
        ArgumentNullException.ThrowIfNull(methods);

        _methods = methods.ToList();
        _methodsByName = _methods.ToDictionary(m => m.MethodName, StringComparer.OrdinalIgnoreCase);

        if (_methods.Count == 0)
        {
            throw new ArgumentException("At least one DID method implementation must be provided", nameof(methods));
        }
    }

    /// <summary>
    /// Gets a DID method implementation by name.
    /// </summary>
    /// <param name="methodName">Method name (e.g., "key", "web")</param>
    /// <returns>The DID method implementation</returns>
    /// <exception cref="NotSupportedException">Thrown if the method is not supported</exception>
    public IDidMethod GetMethod(string methodName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(methodName);

        if (_methodsByName.TryGetValue(methodName, out IDidMethod? method))
        {
            return method;
        }

        throw new NotSupportedException(
            $"DID method '{methodName}' is not supported. Supported methods: {string.Join(", ", _methodsByName.Keys)}");
    }

    /// <summary>
    /// Gets a DID method implementation that can handle the given DID identifier.
    /// </summary>
    /// <param name="did">Full DID identifier</param>
    /// <returns>The DID method implementation that can handle this DID</returns>
    /// <exception cref="NotSupportedException">Thrown if no method can handle the DID</exception>
    public IDidMethod GetMethodForDid(string did)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(did);

        IDidMethod? method = _methods.FirstOrDefault(m => m.CanHandle(did));

        if (method == null)
        {
            throw new NotSupportedException(
                $"No DID method can handle '{did}'. Supported methods: {string.Join(", ", _methodsByName.Keys)}");
        }

        return method;
    }

    /// <summary>
    /// Checks if the given DID method is supported.
    /// </summary>
    /// <param name="methodName">Method name to check</param>
    /// <returns>True if supported, false otherwise</returns>
    public bool IsMethodSupported(string methodName)
    {
        return !string.IsNullOrWhiteSpace(methodName) &&
               _methodsByName.ContainsKey(methodName);
    }

    /// <summary>
    /// Checks if any registered method can handle the given DID identifier.
    /// </summary>
    /// <param name="did">DID identifier to check</param>
    /// <returns>True if a method can handle it, false otherwise</returns>
    public bool CanResolveDid(string did)
    {
        return !string.IsNullOrWhiteSpace(did) &&
               _methods.Any(m => m.CanHandle(did));
    }

    /// <summary>
    /// Gets all supported DID method names.
    /// </summary>
    public IEnumerable<string> SupportedMethods => _methodsByName.Keys;
}
