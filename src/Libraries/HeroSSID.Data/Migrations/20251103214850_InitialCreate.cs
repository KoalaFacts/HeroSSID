using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable IDE0161 // Convert to file-scoped namespace - Generated code
#pragma warning disable CA1062 // Validate arguments of public methods - Generated migration code
#pragma warning disable CA1825 // Avoid zero-length array allocations - Generated code
#pragma warning disable CA1861 // Avoid constant arrays as arguments - Generated code

namespace HeroSSID.Data.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "credential_offers",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    tenant_id = table.Column<string>(type: "text", nullable: false),
                    offer_uri = table.Column<string>(type: "character varying(2048)", maxLength: 2048, nullable: false),
                    credential_issuer = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    pre_authorized_code_id = table.Column<Guid>(type: "uuid", nullable: false),
                    qr_code_image = table.Column<byte[]>(type: "bytea", nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamptz", nullable: false, defaultValueSql: "NOW()"),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamptz", nullable: false),
                    accessed_at = table.Column<DateTimeOffset>(type: "timestamptz", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_credential_offers", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "dids",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                    did_identifier = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    public_key_ed25519 = table.Column<byte[]>(type: "bytea", nullable: false),
                    key_fingerprint = table.Column<byte[]>(type: "bytea", maxLength: 32, nullable: false),
                    private_key_ed25519_encrypted = table.Column<byte[]>(type: "bytea", nullable: false),
                    did_document_json = table.Column<string>(type: "jsonb", nullable: false),
                    status = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false, defaultValue: "active"),
                    created_at = table.Column<DateTimeOffset>(type: "timestamptz", nullable: false, defaultValueSql: "NOW()")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_dids", x => x.id);
                    table.CheckConstraint("chk_did_status", "status IN ('active', 'deactivated')");
                });

            migrationBuilder.CreateTable(
                name: "oauth_clients",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    client_id = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    client_secret_hash = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    display_name = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                    scopes = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: false),
                    is_enabled = table.Column<bool>(type: "boolean", nullable: false, defaultValue: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamptz", nullable: false, defaultValueSql: "NOW()")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_oauth_clients", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "pre_authorized_codes",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    code = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    credential_offer_id = table.Column<Guid>(type: "uuid", nullable: false),
                    tenant_id = table.Column<string>(type: "text", nullable: false),
                    issuer_did_id = table.Column<Guid>(type: "uuid", nullable: false),
                    holder_did_id = table.Column<Guid>(type: "uuid", nullable: true),
                    credential_types = table.Column<string>(type: "jsonb", nullable: false),
                    credential_subject = table.Column<string>(type: "jsonb", nullable: false),
                    transaction_code = table.Column<string>(type: "character varying(6)", maxLength: 6, nullable: true),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamptz", nullable: false),
                    redeemed_at = table.Column<DateTimeOffset>(type: "timestamptz", nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamptz", nullable: false, defaultValueSql: "NOW()"),
                    is_revoked = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_pre_authorized_codes", x => x.id);
                    table.ForeignKey(
                        name: "FK_pre_authorized_codes_credential_offers_credential_offer_id",
                        column: x => x.credential_offer_id,
                        principalTable: "credential_offers",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_pre_authorized_codes_dids_holder_did_id",
                        column: x => x.holder_did_id,
                        principalTable: "dids",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_pre_authorized_codes_dids_issuer_did_id",
                        column: x => x.issuer_did_id,
                        principalTable: "dids",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "presentation_requests",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    tenant_id = table.Column<string>(type: "text", nullable: false),
                    verifier_did_id = table.Column<Guid>(type: "uuid", nullable: true),
                    presentation_definition_json = table.Column<string>(type: "jsonb", nullable: false),
                    nonce = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    response_uri = table.Column<string>(type: "character varying(2048)", maxLength: 2048, nullable: false),
                    request_uri = table.Column<string>(type: "character varying(2048)", maxLength: 2048, nullable: false),
                    state = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamptz", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamptz", nullable: false, defaultValueSql: "NOW()"),
                    responded_at = table.Column<DateTimeOffset>(type: "timestamptz", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_presentation_requests", x => x.id);
                    table.ForeignKey(
                        name: "FK_presentation_requests_dids_verifier_did_id",
                        column: x => x.verifier_did_id,
                        principalTable: "dids",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "verifiable_credentials",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    tenant_id = table.Column<Guid>(type: "uuid", nullable: false),
                    issuer_did_id = table.Column<Guid>(type: "uuid", nullable: false),
                    holder_did_id = table.Column<Guid>(type: "uuid", nullable: false),
                    credential_type = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    credential_jwt = table.Column<string>(type: "text", nullable: false),
                    status = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false, defaultValue: "active"),
                    RevokedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    issued_at = table.Column<DateTimeOffset>(type: "timestamptz", nullable: false, defaultValueSql: "NOW()"),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamptz", nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamptz", nullable: false, defaultValueSql: "NOW()"),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamptz", nullable: false, defaultValueSql: "NOW()")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_verifiable_credentials", x => x.id);
                    table.CheckConstraint("chk_credentials_expiration", "expires_at IS NULL OR expires_at > issued_at");
                    table.ForeignKey(
                        name: "fk_credentials_holder",
                        column: x => x.holder_did_id,
                        principalTable: "dids",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_credentials_issuer",
                        column: x => x.issuer_did_id,
                        principalTable: "dids",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "vp_token_submissions",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    presentation_request_id = table.Column<Guid>(type: "uuid", nullable: false),
                    tenant_id = table.Column<string>(type: "text", nullable: false),
                    vp_token = table.Column<string>(type: "character varying(102400)", maxLength: 102400, nullable: false),
                    disclosed_claims = table.Column<string>(type: "jsonb", nullable: true),
                    holder_did_id = table.Column<Guid>(type: "uuid", nullable: true),
                    verification_status = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    verification_errors = table.Column<string>(type: "jsonb", nullable: true),
                    submitted_at = table.Column<DateTimeOffset>(type: "timestamptz", nullable: false, defaultValueSql: "NOW()"),
                    verified_at = table.Column<DateTimeOffset>(type: "timestamptz", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_vp_token_submissions", x => x.id);
                    table.ForeignKey(
                        name: "FK_vp_token_submissions_dids_holder_did_id",
                        column: x => x.holder_did_id,
                        principalTable: "dids",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_vp_token_submissions_presentation_requests_presentation_req~",
                        column: x => x.presentation_request_id,
                        principalTable: "presentation_requests",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "idx_offer_preauth_code",
                table: "credential_offers",
                column: "pre_authorized_code_id");

            migrationBuilder.CreateIndex(
                name: "idx_offer_tenant",
                table: "credential_offers",
                column: "tenant_id");

            migrationBuilder.CreateIndex(
                name: "idx_dids_identifier",
                table: "dids",
                column: "did_identifier",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "idx_dids_status",
                table: "dids",
                column: "status");

            migrationBuilder.CreateIndex(
                name: "idx_dids_tenant",
                table: "dids",
                column: "tenant_id");

            migrationBuilder.CreateIndex(
                name: "idx_dids_tenant_key_fingerprint",
                table: "dids",
                columns: new[] { "tenant_id", "key_fingerprint" });

            migrationBuilder.CreateIndex(
                name: "idx_oauth_clients_client_id",
                table: "oauth_clients",
                column: "client_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "idx_oauth_clients_tenant",
                table: "oauth_clients",
                column: "tenant_id");

            migrationBuilder.CreateIndex(
                name: "idx_preauth_code",
                table: "pre_authorized_codes",
                column: "code",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "idx_preauth_expires",
                table: "pre_authorized_codes",
                column: "expires_at");

            migrationBuilder.CreateIndex(
                name: "idx_preauth_tenant",
                table: "pre_authorized_codes",
                column: "tenant_id");

            migrationBuilder.CreateIndex(
                name: "IX_pre_authorized_codes_credential_offer_id",
                table: "pre_authorized_codes",
                column: "credential_offer_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_pre_authorized_codes_holder_did_id",
                table: "pre_authorized_codes",
                column: "holder_did_id");

            migrationBuilder.CreateIndex(
                name: "IX_pre_authorized_codes_issuer_did_id",
                table: "pre_authorized_codes",
                column: "issuer_did_id");

            migrationBuilder.CreateIndex(
                name: "idx_presentation_expires",
                table: "presentation_requests",
                column: "expires_at");

            migrationBuilder.CreateIndex(
                name: "idx_presentation_nonce",
                table: "presentation_requests",
                column: "nonce",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "idx_presentation_tenant",
                table: "presentation_requests",
                column: "tenant_id");

            migrationBuilder.CreateIndex(
                name: "IX_presentation_requests_verifier_did_id",
                table: "presentation_requests",
                column: "verifier_did_id");

            migrationBuilder.CreateIndex(
                name: "idx_credentials_expires_at",
                table: "verifiable_credentials",
                column: "expires_at",
                filter: "expires_at IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "idx_credentials_holder",
                table: "verifiable_credentials",
                column: "holder_did_id");

            migrationBuilder.CreateIndex(
                name: "idx_credentials_issued_at",
                table: "verifiable_credentials",
                column: "issued_at",
                descending: new bool[0]);

            migrationBuilder.CreateIndex(
                name: "idx_credentials_issuer",
                table: "verifiable_credentials",
                column: "issuer_did_id");

            migrationBuilder.CreateIndex(
                name: "idx_credentials_tenant",
                table: "verifiable_credentials",
                column: "tenant_id");

            migrationBuilder.CreateIndex(
                name: "idx_credentials_tenant_type_issued",
                table: "verifiable_credentials",
                columns: new[] { "tenant_id", "credential_type", "issued_at" },
                descending: new[] { false, false, true });

            migrationBuilder.CreateIndex(
                name: "idx_credentials_type",
                table: "verifiable_credentials",
                column: "credential_type");

            migrationBuilder.CreateIndex(
                name: "idx_vptoken_presentation",
                table: "vp_token_submissions",
                column: "presentation_request_id");

            migrationBuilder.CreateIndex(
                name: "idx_vptoken_status",
                table: "vp_token_submissions",
                column: "verification_status");

            migrationBuilder.CreateIndex(
                name: "idx_vptoken_tenant",
                table: "vp_token_submissions",
                column: "tenant_id");

            migrationBuilder.CreateIndex(
                name: "IX_vp_token_submissions_holder_did_id",
                table: "vp_token_submissions",
                column: "holder_did_id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "oauth_clients");

            migrationBuilder.DropTable(
                name: "pre_authorized_codes");

            migrationBuilder.DropTable(
                name: "verifiable_credentials");

            migrationBuilder.DropTable(
                name: "vp_token_submissions");

            migrationBuilder.DropTable(
                name: "credential_offers");

            migrationBuilder.DropTable(
                name: "presentation_requests");

            migrationBuilder.DropTable(
                name: "dids");
        }
    }
}
