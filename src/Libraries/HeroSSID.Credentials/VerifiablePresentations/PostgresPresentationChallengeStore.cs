using System.Security.Cryptography;
using HeroSSID.Credentials.Utilities;
using Npgsql;

namespace HeroSSID.Credentials.VerifiablePresentations;

/// <summary>
/// Shared PostgreSQL challenge storage with atomic issuance capacity and one-time consumption.
/// </summary>
/// <remarks>
/// The host owns the data source and must apply the PresentationChallenges migration first.
/// Synchronous operations preserve the existing challenge-store interface; hosts should account
/// for database I/O when planning throughput. An unavailable database fails closed.
/// </remarks>
public sealed class PostgresPresentationChallengeStore : IPresentationChallengeStore
{
    private readonly NpgsqlDataSource _dataSource;
    private readonly TimeProvider _timeProvider;
    private readonly int _capacity;

    /// <summary>Creates a shared store from a configured PostgreSQL connection pool.</summary>
    public PostgresPresentationChallengeStore(NpgsqlDataSource dataSource, TimeProvider timeProvider, int capacity = 1024)
    {
        ArgumentNullException.ThrowIfNull(dataSource);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(capacity);
        _dataSource = dataSource;
        _timeProvider = timeProvider;
        _capacity = capacity;
    }

    /// <inheritdoc />
    public PresentationChallenge Issue(Guid verifierTenantId, string audience, string trustedIssuerDid, TimeSpan? lifetime = null)
    {
        if (verifierTenantId == Guid.Empty)
        {
            throw new ArgumentException("A non-empty verifier tenant is required.", nameof(verifierTenantId));
        }

        ValidateIdentifier(audience, nameof(audience));
        ValidateIdentifier(trustedIssuerDid, nameof(trustedIssuerDid));
        var duration = lifetime ?? TimeSpan.FromMinutes(2);
        if (duration < TimeSpan.FromSeconds(1) || duration > InMemoryPresentationChallengeStore.MaximumLifetime)
        {
            throw new ArgumentOutOfRangeException(nameof(lifetime), "Challenge lifetime must be between one second and five minutes.");
        }

        var now = _timeProvider.GetUtcNow();
        var expiry = DateTimeOffset.FromUnixTimeSeconds(now.Add(duration).ToUnixTimeSeconds());
        using var connection = _dataSource.OpenConnection();
        using var transaction = connection.BeginTransaction();

        // One transaction-scoped advisory lock coordinates admission across all application replicas.
        // Do not split the count and insert into different transactions.
        using (var admissionLock = new NpgsqlCommand(
            "SELECT pg_advisory_xact_lock(1213416281, 1128475468)", connection, transaction))
        {
            admissionLock.ExecuteNonQuery();
        }

        using (var cleanup = new NpgsqlCommand(
            "DELETE FROM presentation_challenges WHERE expires_at <= @now", connection, transaction))
        {
            cleanup.Parameters.AddWithValue("now", now);
            cleanup.ExecuteNonQuery();
        }

        using (var countCommand = new NpgsqlCommand(
            "SELECT count(*) FROM presentation_challenges WHERE consumed_at IS NULL", connection, transaction))
        {
            var outstanding = (long)countCommand.ExecuteScalar()!;
            if (outstanding >= _capacity)
            {
                throw new InvalidOperationException("The outstanding presentation challenge limit has been reached.");
            }
        }

        for (var attempt = 0; attempt < 5; attempt++)
        {
            var nonce = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
            using var insert = new NpgsqlCommand(
                """
                INSERT INTO presentation_challenges
                    (nonce, verifier_tenant_id, audience, trusted_issuer_did, expires_at)
                VALUES (@nonce, @tenant, @audience, @issuer, @expiry)
                ON CONFLICT (nonce) DO NOTHING
                RETURNING nonce
                """, connection, transaction);
            insert.Parameters.AddWithValue("nonce", nonce);
            insert.Parameters.AddWithValue("tenant", verifierTenantId);
            insert.Parameters.AddWithValue("audience", audience);
            insert.Parameters.AddWithValue("issuer", trustedIssuerDid);
            insert.Parameters.AddWithValue("expiry", expiry);
            if (insert.ExecuteScalar() is string)
            {
                transaction.Commit();
                return new PresentationChallenge
                {
                    Nonce = nonce,
                    Audience = audience,
                    TrustedIssuerDid = trustedIssuerDid,
                    ExpiresAt = expiry
                };
            }
        }

        // Collision retries are bounded and never overwrite an existing verifier's challenge.
        throw new InvalidOperationException("A unique presentation challenge could not be issued.");
    }

    /// <inheritdoc />
    public PresentationChallenge? Find(Guid verifierTenantId, string audience, string nonce)
    {
        if (verifierTenantId == Guid.Empty || string.IsNullOrEmpty(audience) ||
            string.IsNullOrEmpty(nonce) || nonce.Length != 43)
        {
            return null;
        }

        using var connection = _dataSource.OpenConnection();
        using var command = new NpgsqlCommand(
            """
            SELECT trusted_issuer_did, expires_at
            FROM presentation_challenges
            WHERE nonce = @nonce AND verifier_tenant_id = @tenant
                AND audience COLLATE "C" = @audience
                AND consumed_at IS NULL AND expires_at > @now
            """, connection);
        command.Parameters.AddWithValue("nonce", nonce);
        command.Parameters.AddWithValue("tenant", verifierTenantId);
        command.Parameters.AddWithValue("audience", audience);
        command.Parameters.AddWithValue("now", _timeProvider.GetUtcNow());
        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return null;
        }

        return new PresentationChallenge
        {
            Nonce = nonce,
            Audience = audience,
            TrustedIssuerDid = reader.GetString(0),
            ExpiresAt = reader.GetFieldValue<DateTimeOffset>(1)
        };
    }

    /// <inheritdoc />
    public bool TryConsume(Guid verifierTenantId, string audience, string nonce)
    {
        if (verifierTenantId == Guid.Empty || string.IsNullOrEmpty(audience) ||
            string.IsNullOrEmpty(nonce) || nonce.Length != 43)
        {
            return false;
        }

        using var connection = _dataSource.OpenConnection();
        using var command = new NpgsqlCommand(
            """
            UPDATE presentation_challenges SET consumed_at = @now
            WHERE nonce = @nonce AND verifier_tenant_id = @tenant
                AND audience COLLATE "C" = @audience
                AND consumed_at IS NULL AND expires_at > @now
            """, connection);
        command.Parameters.AddWithValue("nonce", nonce);
        command.Parameters.AddWithValue("tenant", verifierTenantId);
        command.Parameters.AddWithValue("audience", audience);
        command.Parameters.AddWithValue("now", _timeProvider.GetUtcNow());
        return command.ExecuteNonQuery() == 1;
    }

    private static void ValidateIdentifier(string value, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        if (value.Length > 2048)
        {
            throw new ArgumentException("Identifier exceeds the 2048-character limit.", parameterName);
        }
    }
}
