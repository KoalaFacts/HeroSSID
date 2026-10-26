using System.Data;
using System.Security.Cryptography;
using HeroSSID.Credentials.Utilities;
using Npgsql;

namespace HeroSSID.Credentials.VerifiablePresentations;

/// <summary>Shared PostgreSQL challenge storage with bounded retention and atomic one-time consumption.</summary>
/// <remarks>
/// The host owns the data source and applies the PresentationChallenges migration explicitly.
/// Operations are synchronous. All replicas must use the same capacity settings and synchronized clocks.
/// Consumed rows count towards capacity until expiry; database unavailability fails closed.
/// </remarks>
public sealed class PostgresPresentationChallengeStore : IPresentationChallengeStore
{
    private readonly NpgsqlDataSource _dataSource;
    private readonly TimeProvider _timeProvider;
    private readonly int _capacity;
    private readonly int _tenantCapacity;

    /// <summary>Creates a shared store. Default retained-row limits are 1024 globally and 128 per tenant.</summary>
    public PostgresPresentationChallengeStore(NpgsqlDataSource dataSource, TimeProvider timeProvider,
        int capacity = 1024, int? tenantCapacity = null)
    {
        ArgumentNullException.ThrowIfNull(dataSource);
        ArgumentNullException.ThrowIfNull(timeProvider);
        _tenantCapacity = PresentationChallengePolicy.TenantCapacity(capacity, tenantCapacity);
        _dataSource = dataSource;
        _timeProvider = timeProvider;
        _capacity = capacity;
    }

    /// <inheritdoc />
    public PresentationChallenge Issue(Guid verifierTenantId, string audience, string trustedIssuerDid, TimeSpan? lifetime = null)
    {
        var duration = PresentationChallengePolicy.Validate(verifierTenantId, audience, trustedIssuerDid, lifetime);
        using var connection = _dataSource.OpenConnection();
        using var transaction = connection.BeginTransaction(IsolationLevel.ReadCommitted);

        // Keep cleanup, retained-row accounting and insertion in one cross-replica admission transaction.
        using (var admissionLock = new NpgsqlCommand(
            "SELECT pg_advisory_xact_lock(1213416281, 1128475468)", connection, transaction))
        {
            admissionLock.ExecuteNonQuery();
        }

        // Sample only after a potentially blocking connection/admission wait.
        using (var cleanup = new NpgsqlCommand(
            "DELETE FROM presentation_challenges WHERE expires_at <= GREATEST(@now, clock_timestamp())", connection, transaction))
        {
            cleanup.Parameters.AddWithValue("now", _timeProvider.GetUtcNow());
            cleanup.ExecuteNonQuery();
        }

        // Retain consumed rows as replay tombstones without allowing churn to bypass the storage ceiling.
        using (var count = new NpgsqlCommand(
            "SELECT count(*), count(*) FILTER (WHERE verifier_tenant_id = @tenant) FROM presentation_challenges", connection, transaction))
        {
            count.Parameters.AddWithValue("tenant", verifierTenantId);
            using var reader = count.ExecuteReader();
            reader.Read();
            if (reader.GetInt64(0) >= _capacity || reader.GetInt64(1) >= _tenantCapacity)
            {
                throw new InvalidOperationException("The retained presentation challenge limit has been reached.");
            }
        }

        for (var attempt = 0; attempt < 5; attempt++)
        {
            // Cleanup can itself wait for a consuming transaction; do not spend that wait out of the new lifetime.
            var expiry = PresentationChallengePolicy.Expiry(_timeProvider.GetUtcNow(), duration);
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
                    Nonce = nonce, Audience = audience, TrustedIssuerDid = trustedIssuerDid, ExpiresAt = expiry
                };
            }
        }

        throw new InvalidOperationException("A unique presentation challenge could not be issued.");
    }

    /// <inheritdoc />
    public PresentationChallenge? Find(Guid verifierTenantId, string audience, string nonce)
    {
        if (!PresentationChallengePolicy.IsValidLookup(verifierTenantId, audience, nonce))
        {
            return null;
        }

        using var connection = _dataSource.OpenConnection();
        using var command = new NpgsqlCommand(
            """
            SELECT trusted_issuer_did, expires_at
            FROM presentation_challenges
            WHERE nonce COLLATE "C" = @nonce AND verifier_tenant_id = @tenant
                AND audience COLLATE "C" = @audience AND consumed_at IS NULL
                AND expires_at > GREATEST(@now, clock_timestamp())
            """, connection);
        AddLookupParameters(command, verifierTenantId, audience, nonce);
        command.Parameters.AddWithValue("now", _timeProvider.GetUtcNow());
        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return null;
        }

        var expiry = reader.GetFieldValue<DateTimeOffset>(1);
        if (expiry <= _timeProvider.GetUtcNow())
        {
            return null;
        }

        return new PresentationChallenge
        {
            Nonce = nonce, Audience = audience, TrustedIssuerDid = reader.GetString(0), ExpiresAt = expiry
        };
    }

    /// <inheritdoc />
    public bool TryConsume(Guid verifierTenantId, string audience, string nonce)
    {
        if (!PresentationChallengePolicy.IsValidLookup(verifierTenantId, audience, nonce))
        {
            return false;
        }

        using var connection = _dataSource.OpenConnection();
        using var transaction = connection.BeginTransaction(IsolationLevel.ReadCommitted);
        using (var rowLock = new NpgsqlCommand(
            """
            SELECT 1 FROM presentation_challenges
            WHERE nonce COLLATE "C" = @nonce AND verifier_tenant_id = @tenant
                AND audience COLLATE "C" = @audience AND consumed_at IS NULL
            FOR UPDATE
            """, connection, transaction))
        {
            AddLookupParameters(rowLock, verifierTenantId, audience, nonce);
            if (rowLock.ExecuteScalar() == null)
            {
                return false;
            }
        }

        // Re-sample after acquiring the row lock. The server wall clock additionally covers network/statement delay.
        // ReadCommitted rechecks the consumed predicate after another consumer commits; only one can proceed.
        using var consume = new NpgsqlCommand(
            """
            UPDATE presentation_challenges SET consumed_at = GREATEST(@now, clock_timestamp())
            WHERE nonce COLLATE "C" = @nonce AND verifier_tenant_id = @tenant
                AND audience COLLATE "C" = @audience AND consumed_at IS NULL
                AND expires_at > GREATEST(@now, clock_timestamp())
            """, connection, transaction);
        AddLookupParameters(consume, verifierTenantId, audience, nonce);
        consume.Parameters.AddWithValue("now", _timeProvider.GetUtcNow());
        var accepted = consume.ExecuteNonQuery() == 1;
        transaction.Commit();
        return accepted;
    }

    private static void AddLookupParameters(NpgsqlCommand command, Guid tenant, string audience, string nonce)
    {
        command.Parameters.AddWithValue("nonce", nonce);
        command.Parameters.AddWithValue("tenant", tenant);
        command.Parameters.AddWithValue("audience", audience);
    }
}
