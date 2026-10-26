using System;
using HeroSSID.Data;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace HeroSSID.Data.Migrations;

/// <summary>Durable verifier-owned challenge storage, separate from unfinished OpenID4VP request records.</summary>
[DbContext(typeof(HeroDbContext))]
[Migration("20261025033000_PresentationChallenges")]
public sealed class PresentationChallenges : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        ArgumentNullException.ThrowIfNull(migrationBuilder);
        migrationBuilder.CreateTable(
            name: "presentation_challenges",
            columns: table => new
            {
                nonce = table.Column<string>(type: "character varying(43)", maxLength: 43, nullable: false, collation: "C"),
                verifier_tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                audience = table.Column<string>(type: "character varying(2048)", maxLength: 2048, nullable: false, collation: "C"),
                trusted_issuer_did = table.Column<string>(type: "character varying(2048)", maxLength: 2048, nullable: false),
                expires_at = table.Column<DateTimeOffset>(type: "timestamptz", nullable: false),
                consumed_at = table.Column<DateTimeOffset>(type: "timestamptz", nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("pk_presentation_challenges", x => x.nonce);
                table.CheckConstraint("chk_presentation_challenges_nonce_length", "char_length(nonce) = 43");
            });

        migrationBuilder.CreateIndex(
            name: "idx_presentation_challenges_expiry",
            table: "presentation_challenges",
            column: "expires_at");
        migrationBuilder.CreateIndex(
            name: "idx_presentation_challenges_outstanding",
            table: "presentation_challenges",
            column: "consumed_at",
            filter: "consumed_at IS NULL");
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        ArgumentNullException.ThrowIfNull(migrationBuilder);
        migrationBuilder.DropTable(name: "presentation_challenges");
    }
}
