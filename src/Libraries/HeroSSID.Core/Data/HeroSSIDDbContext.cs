using HeroSSID.Core.Entities;
using Microsoft.EntityFrameworkCore;

namespace HeroSSID.Core.Data;

/// <summary>
/// Entity Framework DbContext for HeroSSID
/// </summary>
public sealed class HeroSSIDDbContext : DbContext
{
    public HeroSSIDDbContext(DbContextOptions<HeroSSIDDbContext> options)
        : base(options)
    {
    }

    /// <summary>
    /// DIDs stored in the system
    /// </summary>
    public DbSet<DidEntity> Dids => Set<DidEntity>();

    /// <summary>
    /// Verifiable Credentials stored in the system
    /// </summary>
    public DbSet<CredentialEntity> Credentials => Set<CredentialEntity>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);

        base.OnModelCreating(modelBuilder);

        // Configure DidEntity
        modelBuilder.Entity<DidEntity>(entity =>
        {
            entity.ToTable("dids");
            entity.HasKey(e => e.Id);

            entity.Property(e => e.Did)
                .IsRequired()
                .HasMaxLength(200);

            entity.HasIndex(e => e.Did)
                .IsUnique();

            entity.Property(e => e.Method)
                .IsRequired()
                .HasMaxLength(50);

            entity.Property(e => e.EncryptedPrivateKey)
                .IsRequired();

            entity.Property(e => e.PublicKeyJwk)
                .IsRequired()
                .HasMaxLength(2000);

            entity.Property(e => e.DidDocument)
                .IsRequired()
                .HasMaxLength(10000);

            entity.Property(e => e.Alias)
                .HasMaxLength(100);

            entity.HasIndex(e => e.Alias);

            entity.Property(e => e.IsActive)
                .IsRequired()
                .HasDefaultValue(true);

            entity.Property(e => e.CreatedAt)
                .IsRequired();

            entity.Property(e => e.LastUsedAt);

            // Configure relationships
            entity.HasMany(e => e.IssuedCredentials)
                .WithOne(c => c.IssuerDid)
                .HasForeignKey(c => c.IssuerDidId)
                .OnDelete(DeleteBehavior.Restrict);

            entity.HasMany(e => e.ReceivedCredentials)
                .WithOne(c => c.SubjectDid)
                .HasForeignKey(c => c.SubjectDidId)
                .OnDelete(DeleteBehavior.Restrict);
        });

        // Configure CredentialEntity
        modelBuilder.Entity<CredentialEntity>(entity =>
        {
            entity.ToTable("credentials");
            entity.HasKey(e => e.Id);

            entity.Property(e => e.Jwt)
                .IsRequired()
                .HasMaxLength(10000);

            entity.Property(e => e.IssuerDidId)
                .IsRequired();

            entity.Property(e => e.SubjectDidId)
                .IsRequired();

            entity.Property(e => e.CredentialType)
                .IsRequired()
                .HasMaxLength(200);

            entity.HasIndex(e => e.CredentialType);

            entity.Property(e => e.CredentialSubject)
                .IsRequired()
                .HasMaxLength(10000);

            entity.Property(e => e.IssuedAt)
                .IsRequired();

            entity.Property(e => e.ExpiresAt);

            entity.Property(e => e.IsRevoked)
                .IsRequired()
                .HasDefaultValue(false);

            entity.Property(e => e.RevokedAt);

            entity.Property(e => e.CreatedAt)
                .IsRequired();

            // Indexes for common queries
            entity.HasIndex(e => e.IssuedAt);
            entity.HasIndex(e => e.IsRevoked);
            entity.HasIndex(e => new { e.IssuerDidId, e.IssuedAt });
            entity.HasIndex(e => new { e.SubjectDidId, e.IssuedAt });
        });
    }
}
