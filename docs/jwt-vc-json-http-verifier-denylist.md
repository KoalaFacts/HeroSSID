# Verifier-owned VC1.1 JWT emergency denial over authenticated HTTP (opt-in)

An independent non-.NET relying party sometimes must deny an **exact previously issued** `jwt_vc_json` token while an issuer is unreachable, or while an incident calls the issuer's private signed status into question. This HTTP adapter uses the existing .NET 10 `JwtVcJsonVerifierDenylist` SDK. It **does not** change the JWT, introduce a standard status registry, or transfer the verifier's policy decision to a wallet or issuer.

## Endpoint, authentication and caller-owned policy

Both routes require an authenticated `credential:verify` principal:

- `POST /api/v1/credentials/jwt-vc-json/verify-active-and-retired-with-denylist`
- `POST /api/v1/credentials/jwt-vc-json/verify-active-and-retired-with-denylist-and-status`

The second route **requires** a private, genuine, fresh, **same actual issuer** Ed25519 revocation snapshot in `revocationSnapshot`; the first **rejects** a supplied snapshot to prevent silent status downgrade. The verifier must **always** include `deniedCredentialSha256` on these routes, even when it is an explicitly configured empty array.

```bash
# The authenticated verifier independently obtained and approved:
#   ISSUER_DID, HOLDER_DID, ORIGINAL_JWT, DENIED_SHA256, ACCESS_TOKEN.
# DENIED_SHA256 is SHA-256 hex (lowercase) of the exact original UTF-8
# compact signed JWT. Never generate the denylist from an untrusted wallet
# response without independent incident and enrollment approval.
curl --fail-with-body --request POST "$HEROSSID_URL/api/v1/credentials/jwt-vc-json/verify-active-and-retired-with-denylist" \
  --header "Authorization: Bearer $ACCESS_TOKEN" \
  --header 'Content-Type: application/json' \
  --data @- <<EOF
{
  "credential": "$ORIGINAL_JWT",
  "activeIssuerDids": ["$ISSUER_DID"],
  "retiredCredentialPins": [],
  "deniedCredentialSha256": ["$DENIED_SHA256"],
  "expectedHolderDid": "$HOLDER_DID",
  "expectedCredentialType": "https://issuer.example/credentials#MembershipCredential",
  "subjectContextUri": "https://issuer.example/contexts/membership/v1"
}
EOF
```

To authenticate an exact JWT from a **retired** issuer instead, remove its DID from `activeIssuerDids` and add `{"issuerDid":"did:key:…","credentialSha256":"<original-jwt-sha256>"}` to `retiredCredentialPins`. The verifier must have independently registered this original signed-token fingerprint before trusting it. Signing a newly backdated JWT with a retired key is **not** enough. Current and retired issuer lists must be disjoint.

The JSON body is caller policy, **not a wallet-provided trust certificate**. Trust the access-token caller only according to the verifier's own configuration and safeguards. `deniedCredentialSha256` contains 0–256 **unique, exact 64-character lowercase SHA-256 hex** digests. Uppercase, non-hex, duplicates, missing or >256 values fail with HTTP 400. The same validation applies to active DIDs (maximum 16), retired original JWT pins (maximum 256), and a maximum of 16 distinct issuers. The original compact JWT is bounded to 65,536 characters. A missing issuer trust policy fails closed.

## Results and fail-closed disclosure

For well-formed requests, the response uses HTTP 200 with `status`, `verifiedIssuerDid`, and `verifiedSubject`:

| Status | Meaning | Issuer/subject returned? |
|---|---|---|
| `DeniedByVerifier` | A genuine, otherwise acceptable signed JWT exactly matched this verifier's local SHA-256 denylist | No |
| `IssuerReportedRevoked` | The actual original issuer's authenticated private status reported the token revoked | No |
| `Invalid` | Untrusted, forged, expired, wrong holder/type/context, wrong signed status, or otherwise unacceptable credential | No |
| `SignedButStatusUnchecked` | Original issuer/holder/type/context/signature/expiry passed, and local denylist did not match; issuer status not checked | Yes |
| `SignedNotListed` | All relevant checks passed, and a genuine fresh private issuer snapshot did not list the JWT | Yes |

If an original JWT is both issuer-revoked and verifier-denied, the SDK reports `IssuerReportedRevoked` after verifying the real issuer status; neither result releases the subject. A clean issuer snapshot cannot override the verifier's independent denial. Denial cannot make an otherwise untrusted or expired signed JWT appear genuinely authenticated.

**Downgrade guard:** the older `verify-active-and-retired` and `verify-active-and-retired-with-status` endpoints do not enforce this policy and therefore **reject** a non-null `deniedCredentialSha256` field with HTTP 400, including an empty list. Use a dedicated denylist route to request that guarantee.

## Executable checks

```bash
dotnet test tests/Unit/HeroSSID.Api.Tests/HeroSSID.Api.Tests.csproj \
  --configuration Release \
  --filter FullyQualifiedName~JwtVcJsonVerifierDenylistHttpTests
```

The xUnit suite uses real, separate Ed25519 active issuer, retired issuer, outsider and holder keys and original signed VC1.1 JWTs. It checks current/retired signature trust, exact-JWT local denial, signed-status precedence, valid claim disclosure, invalid/expired/foreign status, malformed/duplicate/oversized policy, and dedicated route authorization metadata. The full repository CI is the authority for build, integration and security checks.

**Operational limits:** This is a verifier-supplied request policy, not a durable shared denylist service; provisioning, authoritative incident intake, tenant-specific authorization, secure storage, synchronization across verifier instances and audit trails belong to the calling verifier. The issuer's status list may be incomplete or stale. Neither signature nor a clean private snapshot establishes holder key control, informed consent, human or organisation identity verification, real-time non-revocation, delegated agent authority, business authorization or third-party Wallet interoperability. No database migration, deployment or release is part of this feature.

See [SDK emergency denial](jwt-vc-json-verifier-emergency-denylist.md), [retired issuer exact-JWT pins](jwt-vc-json-retired-issuer-exact-pins.md), [existing authenticated HTTP verification](jwt-vc-json-retired-issuer-http-profile.md), and [vision](VISION.md).
