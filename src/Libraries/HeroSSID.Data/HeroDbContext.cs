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
    /// Credential Schemas
    /// </summary>
    public DbSet<CredentialSchemaEntity> CredentialSchemas => Set<CredentialSchemaEntity>();

    /// <summary>
    /// Credential Definitions
    /// </summary>
    public DbSet<CredentialDefinitionEntity> CredentialDefinitions => Set<CredentialDefinitionEntity>();

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

        // Configure CredentialSchemaEntity
        modelBuilder.Entity<CredentialSchemaEntity>(entity =>
        {
            entity.ToTable("credential_schemas", t =>
            {
                t.HasCheckConstraint("chk_schema_version_format", "schema_version ~ '^\\d+\\.\\d+(\\.\\d+)?$'");
            });
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasColumnName("id");

            entity.Property(e => e.TenantId)
                .HasColumnName("tenant_id")
                .IsRequired();

            entity.HasIndex(e => e.TenantId).HasDatabaseName("idx_schemas_tenant");

            entity.Property(e => e.SchemaName)
                .HasColumnName("schema_name")
                .HasMaxLength(100)
                .IsRequired();

            entity.Property(e => e.SchemaVersion)
                .HasColumnName("schema_version")
                .HasMaxLength(20)
                .IsRequired();

            entity.Property(e => e.Attributes)
                .HasColumnName("attributes")
                .IsRequired();

            entity.Property(e => e.SchemaId)
                .HasColumnName("ledger_schema_id")
                .HasMaxLength(255)
                .IsRequired();

            entity.HasIndex(e => e.SchemaId)
                .IsUnique()
                .HasDatabaseName("idx_schemas_ledger_id");

            entity.Property(e => e.PublisherDidId)
                .HasColumnName("publisher_did_id")
                .IsRequired();

            entity.HasIndex(e => e.PublisherDidId).HasDatabaseName("idx_schemas_publisher");
            entity.HasIndex(e => new { e.SchemaName, e.SchemaVersion }).HasDatabaseName("idx_schemas_name_version");

            entity.Property(e => e.CreatedAt)
                .HasColumnName("created_at")
                .HasColumnType("timestamptz")
                .IsRequired()
                .HasDefaultValueSql("NOW()");

            // Foreign key to DID
            entity.HasOne(e => e.PublisherDid)
                .WithMany(d => d.PublishedSchemas)
                .HasForeignKey(e => e.PublisherDidId)
                .OnDelete(DeleteBehavior.Restrict)
                .HasConstraintName("fk_schemas_publisher");
        });

        // Configure CredentialDefinitionEntity
        modelBuilder.Entity<CredentialDefinitionEntity>(entity =>
        {
            entity.ToTable("credential_definitions");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasColumnName("id");

            entity.Property(e => e.TenantId)
                .HasColumnName("tenant_id")
                .IsRequired();

            entity.HasIndex(e => e.TenantId).HasDatabaseName("idx_cred_defs_tenant");

            entity.Property(e => e.SchemaId)
                .HasColumnName("schema_id")
                .IsRequired();

            entity.HasIndex(e => e.SchemaId).HasDatabaseName("idx_cred_defs_schema");

            entity.Property(e => e.IssuerDidId)
                .HasColumnName("issuer_did_id")
                .IsRequired();

            entity.HasIndex(e => e.IssuerDidId).HasDatabaseName("idx_cred_defs_issuer");

            entity.Property(e => e.CredentialDefinitionId)
                .HasColumnName("ledger_cred_def_id")
                .HasMaxLength(255)
                .IsRequired();

            entity.HasIndex(e => e.CredentialDefinitionId)
                .IsUnique()
                .HasDatabaseName("idx_cred_defs_ledger_id");

            entity.Property(e => e.SupportsRevocation)
                .HasColumnName("supports_revocation")
                .IsRequired()
                .HasDefaultValue(false);

            entity.Property(e => e.CreatedAt)
                .HasColumnName("created_at")
                .HasColumnType("timestamptz")
                .IsRequired()
                .HasDefaultValueSql("NOW()");

            // Foreign keys
            entity.HasOne(e => e.Schema)
                .WithMany(s => s.CredentialDefinitions)
                .HasForeignKey(e => e.SchemaId)
                .OnDelete(DeleteBehavior.Restrict)
                .HasConstraintName("fk_cred_defs_schema");

            entity.HasOne(e => e.IssuerDid)
                .WithMany(d => d.CredentialDefinitions)
                .HasForeignKey(e => e.IssuerDidId)
                .OnDelete(DeleteBehavior.Restrict)
                .HasConstraintName("fk_cred_defs_issuer");
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

            entity.Property(e => e.SchemaId)
                .HasColumnName("schema_id")
                .IsRequired();

            entity.HasIndex(e => e.SchemaId).HasDatabaseName("idx_credentials_schema");

            entity.Property(e => e.CredentialDefinitionId)
                .HasColumnName("credential_definition_id")
                .IsRequired();

            entity.HasIndex(e => e.CredentialDefinitionId).HasDatabaseName("idx_credentials_cred_def");

            entity.Property(e => e.CredentialJson)
                .HasColumnName("credential_json")
                .HasColumnType("jsonb")
                .IsRequired();

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

            entity.HasOne(e => e.Schema)
                .WithMany(s => s.Credentials)
                .HasForeignKey(e => e.SchemaId)
                .OnDelete(DeleteBehavior.Restrict)
                .HasConstraintName("fk_credentials_schema");

            entity.HasOne(e => e.CredentialDefinition)
                .WithMany(cd => cd.Credentials)
                .HasForeignKey(e => e.CredentialDefinitionId)
                .OnDelete(DeleteBehavior.Restrict)
                .HasConstraintName("fk_credentials_cred_def");
        });
    }
}
