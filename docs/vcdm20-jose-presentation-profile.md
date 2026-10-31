# VCDM 2.0 direct JOSE holder presentation (opt-in, full disclosure)

This .NET10 library profile joins an issuer-controlled direct VC2 credential to a separately holder-signed presentation. It follows the JOSE EnvelopedVerifiableCredential shape from the [W3C VC-JOSE-COSE Recommendation (13 October 2026)](https://www.w3.org/TR/2026/REC-vc-jose-cose-20261013/) and [VC Data Model 2.0](https://www.w3.org/TR/vc-data-model/). It does NOT assert independent wallet interoperability, JSON-LD semantic conformance, or OpenID4VP conformance.

## Real user flow

The verifier, under its authenticated tenant, chooses a trusted issuer under its own policy and issues a one-use challenge with IPresentationChallengeStore. It signs the retained challenge using its own Ed25519 did:key via OfflineSignedPresentationRequest.Create.

The holder independently pins the verifier DID and precise audience. It verifies the request with OfflineSignedPresentationRequest.TryRead, displays the entire issuer credential and destination, and obtains informed consent from the holder BEFORE calling Vcdm20JosePresentation.Create. The library independently verifies the issuer's original direct VC2 signature, signed issuer and holder binding, declared type and pinned HTTPS context. It then signs the VP with the holder-owned Ed25519 seed, with no holder key escrow.

The verifier calls Vcdm20JosePresentation.Check with its own tenant, audience, nonce, issuer-bound challenge store, type, context and clock. It separately verifies actual issuer and holder signatures, exact nonce, audience and expiry; then atomically consumes the stored challenge. If consumption blocks, expiry is rechecked afterwards. A replay, forged signature, wrong issuer, changed context, cross-tenant submission or expired request returns Invalid **without releasing subject claims**.

## Exact bounded wire profile

The holder signs a compact EdDSA JWS with `typ: vp+jwt`, `cty: vp` and `kid` identifying its own `did:key` verification method, following the [W3C VC-JOSE-COSE §3.1.2 (13 October 2026)](https://www.w3.org/TR/2026/REC-vc-jose-cose-20261013/#securing-json-ld-verifiable-presentations-with-jose) content-type recommendation. Verification remains compatible with authentically signed older `vp+jwt` presentations whose optional `cty` is absent; a present mismatched, malformed or duplicate `cty` is rejected before a challenge can be consumed. The direct JWT payload has top-level @context (the VC2 base context), type (VerifiablePresentation), holder, verifiableCredential, aud, nonce, iat and exp. It contains no legacy nested vp/vc claim. The single verifiableCredential is an object with the base @context, type EnvelopedVerifiableCredential, and id equal to data:application/vc+jwt, followed by the **unchanged** issuer JWT. The direct credential must be signed with the issuer's own real Ed25519 seed. Invalid signatures, duplicate JSON properties, unsanctioned shapes, misplaced IDs and long or noncanonical compact tokens fail closed. Times use fractional NumericDates; presentation expiry is bounded by challenge and issuer credential validUntil.

The caller-provided verifier DID and audience MUST be pinned independently. The challenge is not a wallet trust policy, and a DID signature alone does not authenticate an organisation.

## Security and interoperability limitations

- SignedButStatusUnchecked is deliberately NOT named Valid. The direct VC2 issuance path does not persist in the legacy PostgreSQL database, and its legacy revocation snapshots do not cover VC2 tokens. A successful result proves signed issuer provenance and holder-key control, NOT real-time non-revocation, active registration, real-world identity or business authorization.
- Contexts are compared to exact pinned URI strings; this is NOT JSON-LD expansion, canonicalization or semantic validation. Callers must control the claim vocabulary's meaning.
- This is a full-claim-disclosure signing library without a consent UI, hosted HTTP exchange, credential registry, standard status list, third-party wallet test, or conformance certification. The verifier request is the existing private HeroSSID signed request, NOT an OpenID4VP Request Object.
- The verifier retains issuer trust and nonce policy. The in-memory store is single-process only: a multi-replica verifier MUST provision a shared, atomic challenge store, such as the existing PostgreSQL implementation. No schema change is made.
- Seeds are caller-owned; applications must protect and wipe them. No managed signing-key lifecycle, issuer rotation or business grant is implied.

## Minimal usage

The verifier creates a challenge and signs it using OfflineSignedPresentationRequest.Create; the holder calls TryRead with an independently pinned verifier DID and audience, displays every claim, and obtains consent. The holder then calls:

    string presentation = Vcdm20JosePresentation.Create(
        signedRequest, pinnedVerifierDid, "https://verifier.example/check",
        originalIssuerSignedDirectVc2Jwt, "MembershipCredential",
        new Uri("https://issuer.example/contexts/membership/v1"),
        holderDid, holderOwnedEd25519Seed, TimeProvider.System);

The verifier independently calls:

    var outcome = Vcdm20JosePresentation.Check(
        presentation, verifierTenantId, issuedChallenge.Audience,
        issuedChallenge.Nonce, "MembershipCredential",
        new Uri("https://issuer.example/contexts/membership/v1"),
        verifierChallengeStore, TimeProvider.System, out var signedClaims);

Only SignedButStatusUnchecked yields claims, and the calling verifier MUST separately handle status, expiry and business authorization before any decision.
