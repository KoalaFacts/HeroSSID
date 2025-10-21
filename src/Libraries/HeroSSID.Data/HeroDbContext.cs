using HeroSSID.Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace HeroSSID.Data;

/// <summary>
/// Entity Framework DbContext for HeroSSID with W3C SSI data model
/// </summary>
public sealed class HeroDbContext : DbContext
{
    /// <summary>
    /// Hardcoded tenant ID for MVP (will be replaced with multi-tenancy in v2)
    /// </summary>
    public static readonly Guid DefaultTenantId = Guid.Parse("11111111-1111-1111-1111-111111111111");

    public HeroDbContext(DbContextOptions<HeroDbContext> options)
        : base(options)
    {
    }

    /// <summary>
    /// Decentralized Identifiers (DIDs)
    /// </summary>
    public DbSet<DidEntity> Dids => Set<DidEntity>();

    /// <summary>
    /// Verifiable Credentials
    /// </summary>
    public DbSet<VerifiableCredentialEntity> VerifiableCredentials => Set<VerifiableCredentialEntity>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);
        base.OnModelCreating(modelBuilder);

        // Configure DidEntity
        modelBuilder.Entity<DidEntity>(entity =>
        {
            entity.ToTable("dids", t =>
            {
                t.HasCheckConstraint("chk_did_status", "status IN ('active', 'deactivated')");
            });
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasColumnName("id");

            entity.Property(e => e.TenantId)
                .HasColumnName("tenant_id")
                .IsRequired();

            entity.HasIndex(e => e.TenantId).HasDatabaseName("idx_dids_tenant");

            entity.Property(e => e.DidIdentifier)
                .HasColumnName("did_identifier")
                .HasMaxLength(255)
                .IsRequired();

            entity.HasIndex(e => e.DidIdentifier)
                .IsUnique()
                .HasDatabaseName("idx_dids_identifier");

            entity.Property(e => e.PublicKeyEd25519)
                .HasColumnName("public_key_ed25519")
                .IsRequired();

            entity.Property(e => e.KeyFingerprint)
                .HasColumnName("key_fingerprint")
                .IsRequired()
                .HasMaxLength(32); // SHA-256 is 32 bytes

            // SECURITY: Index on key_fingerprint for efficient key reuse detection
            entity.HasIndex(e => new { e.TenantId, e.KeyFingerprint })
                .HasDatabaseName("idx_dids_tenant_key_fingerprint");

            entity.Property(e => e.PrivateKeyEd25519Encrypted)
                .HasColumnName("private_key_ed25519_encrypted")
                .IsRequired();

            entity.Property(e => e.DidDocumentJson)
                .HasColumnName("did_document_json")
                .HasColumnType("jsonb")
                .IsRequired();

            entity.Property(e => e.Status)
                .HasColumnName("status")
                .HasMaxLength(20)
                .IsRequired()
                .HasDefaultValue("active");

            entity.HasIndex(e => e.Status).HasDatabaseName("idx_dids_status");

            entity.Property(e => e.CreatedAt)
                .HasColumnName("created_at")
                .HasColumnType("timestamptz")
                .IsRequired()
                .HasDefaultValueSql("NOW()");

            // Configure relationships
            entity.HasMany(e => e.IssuedCredentials)
                .WithOne(c => c.IssuerDid)
                .HasForeignKey(c => c.IssuerDidId)
                .OnDelete(DeleteBehavior.Restrict);

            entity.HasMany(e => e.HeldCredentials)
                .WithOne(c => c.HolderDid)
                .HasForeignKey(c => c.HolderDidId)
                .OnDelete(DeleteBehavior.Restrict);
        });

        // Configure VerifiableCredentialEntity
        modelBuilder.Entity<VerifiableCredentialEntity>(entity =>
        {
            entity.ToTable("verifiable_credentials", t =>
            {
                t.HasCheckConstraint("chk_credentials_expiration", "expires_at IS NULL OR expires_at > issued_at");
            });
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasColumnName("id");

            entity.Property(e => e.TenantId)
                .HasColumnName("tenant_id")
                .IsRequired();

            entity.HasIndex(e => e.TenantId).HasDatabaseName("idx_credentials_tenant");

            entity.Property(e => e.IssuerDidId)
                .HasColumnName("issuer_did_id")
                .IsRequired();

            entity.HasIndex(e => e.IssuerDidId).HasDatabaseName("idx_credentials_issuer");

            entity.Property(e => e.HolderDidId)
                .HasColumnName("holder_did_id")
                .IsRequired();

            entity.HasIndex(e => e.HolderDidId).HasDatabaseName("idx_credentials_holder");

            entity.Property(e => e.CredentialType)
                .HasColumnName("credential_type")
                .HasMaxLength(256)
                .IsRequired();

            entity.HasIndex(e => e.CredentialType).HasDatabaseName("idx_credentials_type");

            entity.Property(e => e.CredentialJwt)
                .HasColumnName("credential_jwt")
                .HasColumnType("text")
                .IsRequired();

            entity.Property(e => e.Status)
                .HasColumnName("status")
                .HasMaxLength(50)
                .IsRequired()
                .HasDefaultValue("active");

            entity.Property(e => e.IssuedAt)
                .HasColumnName("issued_at")
                .HasColumnType("timestamptz")
                .IsRequired()
                .HasDefaultValueSql("NOW()");

            entity.HasIndex(e => e.IssuedAt)
                .IsDescending()
                .HasDatabaseName("idx_credentials_issued_at");

            entity.Property(e => e.ExpiresAt)
                .HasColumnName("expires_at")
                .HasColumnType("timestamptz");

            // Partial index for non-null expiration dates
            entity.HasIndex(e => e.ExpiresAt)
                .HasFilter("expires_at IS NOT NULL")
                .HasDatabaseName("idx_credentials_expires_at");

            entity.Property(e => e.CreatedAt)
                .HasColumnName("created_at")
                .HasColumnType("timestamptz")
                .IsRequired()
                .HasDefaultValueSql("NOW()");

            entity.Property(e => e.UpdatedAt)
                .HasColumnName("updated_at")
                .HasColumnType("timestamptz")
                .IsRequired()
                .HasDefaultValueSql("NOW()");

            // Composite index for multi-tenant queries
            entity.HasIndex(e => new { e.TenantId, e.CredentialType, e.IssuedAt })
                .IsDescending(false, false, true)
                .HasDatabaseName("idx_credentials_tenant_type_issued");

            // Foreign keys
            entity.HasOne(e => e.IssuerDid)
                .WithMany(d => d.IssuedCredentials)
                .HasForeignKey(e => e.IssuerDidId)
                .OnDelete(DeleteBehavior.Restrict)
                .HasConstraintName("fk_credentials_issuer");

            entity.HasOne(e => e.HolderDid)
                .WithMany(d => d.HeldCredentials)
                .HasForeignKey(e => e.HolderDidId)
                .OnDelete(DeleteBehavior.Restrict)
                .HasConstraintName("fk_credentials_holder");
        });
    }
}
