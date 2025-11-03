using Microsoft.Extensions.Logging;

namespace HeroSSID.Observability;

/// <summary>
/// Wrapper for consistent structured logging across HeroSSID
/// Provides strongly-typed logging methods with structured context
/// </summary>
public sealed class StructuredLogger<T>(ILogger<T> logger)
{
    private readonly ILogger<T> _logger = logger ?? throw new ArgumentNullException(nameof(logger));

    // LoggerMessage delegates
    private static readonly Action<ILogger, string, Guid, Exception?> _logDidCreated =
        LoggerMessage.Define<string, Guid>(
            LogLevel.Information,
            new EventId(1, nameof(LogDidCreated)),
            "DID created: {DidIdentifier} for tenant {TenantId}");

    private static readonly Action<ILogger, string, string, string, Guid, Exception?> _logSchemaPublished =
        LoggerMessage.Define<string, string, string, Guid>(
            LogLevel.Information,
            new EventId(2, nameof(LogSchemaPublished)),
            "Schema published: {SchemaName} v{SchemaVersion} with ledger ID {LedgerSchemaId} for tenant {TenantId}");

    private static readonly Action<ILogger, string, Guid, Guid, Exception?> _logCredentialDefinitionCreated =
        LoggerMessage.Define<string, Guid, Guid>(
            LogLevel.Information,
            new EventId(3, nameof(LogCredentialDefinitionCreated)),
            "Credential definition created: {LedgerCredDefId} for schema {SchemaId} for tenant {TenantId}");

    private static readonly Action<ILogger, Guid, string, string, Guid, Exception?> _logCredentialIssued =
        LoggerMessage.Define<Guid, string, string, Guid>(
            LogLevel.Information,
            new EventId(4, nameof(LogCredentialIssued)),
            "Credential issued: {CredentialId} from issuer {IssuerDid} to holder {HolderDid} for tenant {TenantId}");

    private static readonly Action<ILogger, Guid, bool, Guid, Exception?> _logCredentialVerified =
        LoggerMessage.Define<Guid, bool, Guid>(
            LogLevel.Information,
            new EventId(5, nameof(LogCredentialVerified)),
            "Credential verified: {CredentialId} validity={IsValid} for tenant {TenantId}");

    private static readonly Action<ILogger, string, string, Exception?> _logWalletOperationSuccess =
        LoggerMessage.Define<string, string>(
            LogLevel.Information,
            new EventId(6, nameof(LogWalletOperation)),
            "Wallet operation successful: {Operation} on wallet {WalletId}");

    private static readonly Action<ILogger, string, string, string, Exception?> _logWalletOperationFailed =
        LoggerMessage.Define<string, string, string>(
            LogLevel.Error,
            new EventId(7, nameof(LogWalletOperation)),
            "Wallet operation failed: {Operation} on wallet {WalletId} - {ErrorMessage}");

    private static readonly Action<ILogger, string, string, Exception?> _logLedgerOperationSuccess =
        LoggerMessage.Define<string, string>(
            LogLevel.Information,
            new EventId(8, nameof(LogLedgerOperation)),
            "Ledger operation successful: {Operation} (TxnId: {TransactionId})");

    private static readonly Action<ILogger, string, string, Exception?> _logLedgerOperationFailed =
        LoggerMessage.Define<string, string>(
            LogLevel.Error,
            new EventId(9, nameof(LogLedgerOperation)),
            "Ledger operation failed: {Operation} (TxnId: {TransactionId})");

    private static readonly Action<ILogger, string, string, string, Exception?> _logSecurityEvent =
        LoggerMessage.Define<string, string, string>(
            LogLevel.Warning,
            new EventId(10, nameof(LogSecurityEvent)),
            "Security event: {EventType} - {Description} for tenant {TenantId}");

    private static readonly Action<ILogger, string, string, Exception?> _logError =
        LoggerMessage.Define<string, string>(
            LogLevel.Error,
            new EventId(11, nameof(LogError)),
            "Error during {Operation}: {Context}");

    /// <summary>
    /// Logs DID creation event
    /// </summary>
    public void LogDidCreated(string didIdentifier, Guid tenantId)
    {
        _logDidCreated(_logger, didIdentifier, tenantId, null);
    }

    /// <summary>
    /// Logs credential schema publication
    /// </summary>
    public void LogSchemaPublished(string schemaName, string schemaVersion, string ledgerSchemaId, Guid tenantId)
    {
        _logSchemaPublished(_logger, schemaName, schemaVersion, ledgerSchemaId, tenantId, null);
    }

    /// <summary>
    /// Logs credential definition creation
    /// </summary>
    public void LogCredentialDefinitionCreated(string ledgerCredDefId, Guid schemaId, Guid tenantId)
    {
        _logCredentialDefinitionCreated(_logger, ledgerCredDefId, schemaId, tenantId, null);
    }

    /// <summary>
    /// Logs credential issuance
    /// </summary>
    public void LogCredentialIssued(Guid credentialId, string issuerDid, string holderDid, Guid tenantId)
    {
        _logCredentialIssued(_logger, credentialId, issuerDid, holderDid, tenantId, null);
    }

    /// <summary>
    /// Logs credential verification
    /// </summary>
    public void LogCredentialVerified(Guid credentialId, bool isValid, Guid tenantId)
    {
        _logCredentialVerified(_logger, credentialId, isValid, tenantId, null);
    }

    /// <summary>
    /// Logs wallet operation
    /// </summary>
    public void LogWalletOperation(string operation, string walletId, bool success, string? errorMessage = null)
    {
        if (success)
        {
            _logWalletOperationSuccess(_logger, operation, walletId, null);
        }
        else
        {
            _logWalletOperationFailed(_logger, operation, walletId, errorMessage ?? "Unknown error", null);
        }
    }

    /// <summary>
    /// Logs ledger operation
    /// </summary>
    public void LogLedgerOperation(string operation, string? transactionId = null, bool success = true)
    {
        if (success)
        {
            _logLedgerOperationSuccess(_logger, operation, transactionId ?? "N/A", null);
        }
        else
        {
            _logLedgerOperationFailed(_logger, operation, transactionId ?? "N/A", null);
        }
    }

    /// <summary>
    /// Logs security event
    /// </summary>
    public void LogSecurityEvent(string eventType, string description, Guid? tenantId = null)
    {
        _logSecurityEvent(_logger, eventType, description, tenantId?.ToString() ?? "N/A", null);
    }

    /// <summary>
    /// Logs error with exception
    /// </summary>
    public void LogError(Exception exception, string operation, string? context = null)
    {
        _logError(_logger, operation, context ?? "No additional context", exception);
    }
}
