# Recipient-pinned VC1.1 JWT authenticated HTTP verifier (opt-in)

The standard [VC Data Model 1.1](https://www.w3.org/TR/vc-data-model-1.1/#json-web-token) maps JWT `aud` to a **holder-signed presentation**, not an issuer credential. HeroSSID's explicit SDK `CreateForAudience` issues a **private RFC 7519 application-level recipient restriction** on the original issuer-signed JWT. This is NOT a normative VC1.1 audience binding, complete OpenID4VP exchange or third-party wallet interoperability.

## Execution

A genuine issuer with its own Ed25519 seed calls `JwtVcJsonCredential.CreateForAudience(..., relyingPartyAudience)`. A non-.NET relying party then POSTs to one of:

- `/api/v1/credentials/jwt-vc-json/verify-for-audience`
- `/api/v1/credentials/jwt-vc-json/verify-for-audience-with-status`

Both routes require authenticated `credential:verify`. Request JSON includes `credential` (the **original** issuer-signed JWT), `trustedIssuerDid`, `expectedHolderDid`, `expectedCredentialType`, `subjectContextUri` and `expectedAudience` (a canonical HTTPS URI, no credentials or fragment). All pins **must come from the relying party's independent policy**, never from JWT claims. The SDK also offers `TryVerifyForAudienceWithValidity` to retain signed claim, ID, descriptive name and exact validity bounds after authenticating the original issuer Ed25519 signature.

The unchecked route rejects any submitted `revocationSnapshot` or `minimumStatusObservedAt` with HTTP 400 instead of dropping it. The with-status route requires `revocationSnapshot`, a private issuer-signed 60-second statement over the **exact original JWT**. Optional verifier-owned `minimumStatusObservedAt` rejects previously observed status. A genuine same-issuer non-listing returns `SignedNotListed`, but this does **not** prove a complete set or live non-revocation.

A successfully verified recipient JWT returns `SignedButStatusUnchecked` (or `SignedNotListed` when status passes) with verified subject and original signed validity; wrong recipient, forgery, untrusted issuer/holder, missing audience, stale or foreign status yields `Invalid` or `Revoked` and **no subject/ID/name/date**. Missing or malformed policy gives HTTP 400. The pre-existing HTTP `verify` and `verify-with-status` remain unable to accept audience-bearing credentials and now explicitly reject an unexpected `expectedAudience` policy rather than silently ignoring it.

Unit and actual authenticated HTTP contract tests exercise genuine Ed25519, verified and wrong recipient, route scopes, status and signed-claim suppression. These are internal tests; external Wallet interoperation has **not** been demonstrated. Issuer signature, holder private-key possession, real identity verification, disclosure consent and business authorization are separate decisions. There is no new HTTP issuance route, database schema/migration, release or deployment in this package.

See [the SDK audience profile](jwt-vc-json-recipient-audience.md) and [VISION](VISION.md).
