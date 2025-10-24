using HeroSSID.Data.Entities;
using Microsoft.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;

namespace HeroSSID.Data;

/// <summary>
/// Entity Framework DbContext for HeroSSID with W3C SSI data model
/// </summary>
public sealed class HeroDbContext(DbContextOptions<HeroDbContext> options) : DbContext(options)
{
    /// <summary>
    /// Hardcoded tenant ID for MVP (will be replaced with multi-tenancy in v2)
    /// </summary>
    public static readonly Guid DefaultTenantId = Guid.Parse("11111111-1111-1111-1111-111111111111");

    /// <summary>
    /// Decentralized Identifiers (DIDs)
    /// </summary>
    public DbSet<DidEntity> Dids => Set<DidEntity>();

    /// <summary>
    /// Verifiable Credentials
    /// </summary>
    public DbSet<VerifiableCredentialEntity> VerifiableCredentials => Set<VerifiableCredentialEntity>();

    /// <summary>
    /// Pre-authorized codes for OpenID4VCI
    /// </summary>
    public DbSet<PreAuthorizedCode> PreAuthorizedCodes => Set<PreAuthorizedCode>();

    /// <summary>
    /// Credential offers for wallet integration
    /// </summary>
    public DbSet<CredentialOffer> CredentialOffers => Set<CredentialOffer>();

    /// <summary>
    /// OpenID4VP presentation requests
    /// </summary>
    public DbSet<PresentationRequest> PresentationRequests => Set<PresentationRequest>();

    /// <summary>
    /// VP token submissions from wallets
    /// </summary>
    public DbSet<VpTokenSubmission> VpTokenSubmissions => Set<VpTokenSubmission>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);
        base.OnModelCreating(modelBuilder);

        // Configure OpenIddict tables with tenant-aware entities (CRITICAL-5)
        modelBuilder.UseOpenIddict<TenantAwareOpenIddictApplication, TenantAwareOpenIddictAuthorization, TenantAwareOpenIddictScope, TenantAwareOpenIddictToken, Guid>();

        // Add TenantId to OpenIddict entities
        modelBuilder.Entity<TenantAwareOpenIddictApplication>(entity =>
        {
            entity.Property(e => e.TenantId)
                .HasMaxLength(256)
                .IsRequired();
            entity.HasIndex(e => e.TenantId).HasDatabaseName("idx_openiddict_applications_tenant");
        });

        modelBuilder.Entity<TenantAwareOpenIddictAuthorization>(entity =>
        {
            entity.Property(e => e.TenantId)
                .HasMaxLength(256)
                .IsRequired();
            entity.HasIndex(e => e.TenantId).HasDatabaseName("idx_openiddict_authorizations_tenant");
        });

        modelBuilder.Entity<TenantAwareOpenIddictScope>(entity =>
        {
            entity.Property(e => e.TenantId)
                .HasMaxLength(256)
                .IsRequired();
            entity.HasIndex(e => e.TenantId).HasDatabaseName("idx_openiddict_scopes_tenant");
        });

        modelBuilder.Entity<TenantAwareOpenIddictToken>(entity =>
        {
            entity.Property(e => e.TenantId)
                .HasMaxLength(256)
                .IsRequired();
            entity.HasIndex(e => e.TenantId).HasDatabaseName("idx_openiddict_tokens_tenant");
        });

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

        // Configure PreAuthorizedCode
        modelBuilder.Entity<PreAuthorizedCode>(entity =>
        {
            entity.ToTable("pre_authorized_codes");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasColumnName("id");

            entity.Property(e => e.Code).HasColumnName("code").HasMaxLength(512).IsRequired();
            entity.HasIndex(e => e.Code).IsUnique().HasDatabaseName("idx_preauth_code");

            entity.Property(e => e.TenantId).HasColumnName("tenant_id").IsRequired();
            entity.HasIndex(e => e.TenantId).HasDatabaseName("idx_preauth_tenant");

            entity.Property(e => e.CredentialOfferId).HasColumnName("credential_offer_id").IsRequired();
            entity.Property(e => e.IssuerDidId).HasColumnName("issuer_did_id").IsRequired();
            entity.Property(e => e.HolderDidId).HasColumnName("holder_did_id");

            entity.Property(e => e.CredentialTypes).HasColumnName("credential_types").HasColumnType("jsonb").IsRequired();
            entity.Property(e => e.CredentialSubject).HasColumnName("credential_subject").HasColumnType("jsonb").IsRequired();
            entity.Property(e => e.TransactionCode).HasColumnName("transaction_code").HasMaxLength(6);

            entity.Property(e => e.ExpiresAt).HasColumnName("expires_at").HasColumnType("timestamptz").IsRequired();
            entity.HasIndex(e => e.ExpiresAt).HasDatabaseName("idx_preauth_expires");

            entity.Property(e => e.RedeemedAt).HasColumnName("redeemed_at").HasColumnType("timestamptz");
            entity.Property(e => e.CreatedAt).HasColumnName("created_at").HasColumnType("timestamptz").IsRequired().HasDefaultValueSql("NOW()");
            entity.Property(e => e.IsRevoked).HasColumnName("is_revoked").HasDefaultValue(false);

            entity.HasOne(e => e.IssuerDid).WithMany().HasForeignKey(e => e.IssuerDidId).OnDelete(DeleteBehavior.Restrict);
            entity.HasOne(e => e.HolderDid).WithMany().HasForeignKey(e => e.HolderDidId).OnDelete(DeleteBehavior.Restrict);
            entity.HasOne(e => e.CredentialOffer).WithOne(c => c.PreAuthorizedCode).HasForeignKey<PreAuthorizedCode>(e => e.CredentialOfferId).OnDelete(DeleteBehavior.Cascade);
        });

        // Configure CredentialOffer
        modelBuilder.Entity<CredentialOffer>(entity =>
        {
            entity.ToTable("credential_offers");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasColumnName("id");

            entity.Property(e => e.TenantId).HasColumnName("tenant_id").IsRequired();
            entity.HasIndex(e => e.TenantId).HasDatabaseName("idx_offer_tenant");

            entity.Property(e => e.OfferUri).HasColumnName("offer_uri").HasMaxLength(2048).IsRequired();
            entity.Property(e => e.CredentialIssuer).HasColumnName("credential_issuer").HasMaxLength(512).IsRequired();
            entity.Property(e => e.PreAuthorizedCodeId).HasColumnName("pre_authorized_code_id").IsRequired();
            entity.HasIndex(e => e.PreAuthorizedCodeId).HasDatabaseName("idx_offer_preauth_code");

            entity.Property(e => e.QrCodeImage).HasColumnName("qr_code_image").HasColumnType("bytea");
            entity.Property(e => e.CreatedAt).HasColumnName("created_at").HasColumnType("timestamptz").IsRequired().HasDefaultValueSql("NOW()");
            entity.Property(e => e.ExpiresAt).HasColumnName("expires_at").HasColumnType("timestamptz").IsRequired();
            entity.Property(e => e.AccessedAt).HasColumnName("accessed_at").HasColumnType("timestamptz");
        });

        // Configure PresentationRequest
        modelBuilder.Entity<PresentationRequest>(entity =>
        {
            entity.ToTable("presentation_requests");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasColumnName("id");

            entity.Property(e => e.TenantId).HasColumnName("tenant_id").IsRequired();
            entity.HasIndex(e => e.TenantId).HasDatabaseName("idx_presentation_tenant");

            entity.Property(e => e.VerifierDidId).HasColumnName("verifier_did_id");
            entity.Property(e => e.PresentationDefinitionJson).HasColumnName("presentation_definition_json").HasColumnType("jsonb").IsRequired();

            entity.Property(e => e.Nonce).HasColumnName("nonce").HasMaxLength(512).IsRequired();
            entity.HasIndex(e => e.Nonce).IsUnique().HasDatabaseName("idx_presentation_nonce");

            entity.Property(e => e.ResponseUri).HasColumnName("response_uri").HasMaxLength(2048).IsRequired();
            entity.Property(e => e.RequestUri).HasColumnName("request_uri").HasMaxLength(2048).IsRequired();
            entity.Property(e => e.State).HasColumnName("state").HasMaxLength(512).IsRequired();

            entity.Property(e => e.ExpiresAt).HasColumnName("expires_at").HasColumnType("timestamptz").IsRequired();
            entity.HasIndex(e => e.ExpiresAt).HasDatabaseName("idx_presentation_expires");

            entity.Property(e => e.CreatedAt).HasColumnName("created_at").HasColumnType("timestamptz").IsRequired().HasDefaultValueSql("NOW()");
            entity.Property(e => e.RespondedAt).HasColumnName("responded_at").HasColumnType("timestamptz");

            entity.HasOne(e => e.VerifierDid).WithMany().HasForeignKey(e => e.VerifierDidId).OnDelete(DeleteBehavior.Restrict);
            entity.HasMany(e => e.VpTokenSubmissions).WithOne(v => v.PresentationRequest).HasForeignKey(v => v.PresentationRequestId).OnDelete(DeleteBehavior.Cascade);
        });

        // Configure VpTokenSubmission
        modelBuilder.Entity<VpTokenSubmission>(entity =>
        {
            entity.ToTable("vp_token_submissions");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasColumnName("id");

            entity.Property(e => e.PresentationRequestId).HasColumnName("presentation_request_id").IsRequired();
            entity.HasIndex(e => e.PresentationRequestId).HasDatabaseName("idx_vptoken_presentation");

            entity.Property(e => e.TenantId).HasColumnName("tenant_id").IsRequired();
            entity.HasIndex(e => e.TenantId).HasDatabaseName("idx_vptoken_tenant");

            // CRITICAL-7: VP Token size limit (100KB) to prevent storage attacks
            // JWT tokens with embedded credentials typically range from 2KB-50KB
            // 100KB limit provides safety margin while preventing abuse
            entity.Property(e => e.VpToken).HasColumnName("vp_token").HasMaxLength(102400).IsRequired();
            entity.Property(e => e.DisclosedClaims).HasColumnName("disclosed_claims").HasColumnType("jsonb");
            entity.Property(e => e.HolderDidId).HasColumnName("holder_did_id");

            entity.Property(e => e.VerificationStatus).HasColumnName("verification_status").HasMaxLength(50).IsRequired();
            entity.HasIndex(e => e.VerificationStatus).HasDatabaseName("idx_vptoken_status");

            entity.Property(e => e.VerificationErrors).HasColumnName("verification_errors").HasColumnType("jsonb");
            entity.Property(e => e.SubmittedAt).HasColumnName("submitted_at").HasColumnType("timestamptz").IsRequired().HasDefaultValueSql("NOW()");
            entity.Property(e => e.VerifiedAt).HasColumnName("verified_at").HasColumnType("timestamptz");

            entity.HasOne(e => e.HolderDid).WithMany().HasForeignKey(e => e.HolderDidId).OnDelete(DeleteBehavior.Restrict);
        });
    }
}
