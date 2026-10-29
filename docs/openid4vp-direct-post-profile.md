# OpenID4VP 1.0 direct_post — bounded HeroSSID exchange

Protocol reference: [OpenID for Verifiable Presentations 1.0 Final, 9 July 2025](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html), particularly §§5, 5.9, 6, 8.1, 8.2 and Appendix B.

This development library implements a **small request/response transport profile**, not OpenID4VP conformance, independent-wallet interoperability, or real-world identity checking. It has **no hosted HTTP response endpoint** and does not perform user consent. The caller hosts its own HTTPS \`response_uri\` and handles the form body. It does not fetch untrusted \`request_uri\` links, discover untrusted DIDs, support encryption, cross-device UX, alternative DCQL queries, or third-party credential formats.

## Supported wire exchange

- The verifier independently selects an active, trusted issuer DID and stores a random one-use challenge with \`IPresentationChallengeStore.Issue(verifierTenantId, "decentralized_identifier:" + verifierDid, trustedIssuerDid)\`. For multiple replicas, use the existing PostgreSQL-backed atomic store, not separate process-local stores.
- \`OpenId4VpDirectPost.CreateSignedRequest(challenge, verifierDid, verifierSeed, responseUri, clock)\` creates a DID:key/Ed25519 signed JWT Request Object with \`typ=oauth-authz-req+jwt\` and the DID method \`kid\`. The signed payload uses \`client_id=decentralized_identifier:did:key:...\`, \`aud=https://self-issued.me/v2\`, \`response_type=vp_token\`, \`response_mode=direct_post\`, an **HTTPS** \`response_uri\`, fresh \`nonce\`, \`state=nonce\`, \`dcql_query\`, bounded \`iat/exp\`, and a signed private issuer-policy extension.
- This deployment-defined credential format is **\`herossid_vc_jwt\`**, **not** \`jwt_vc_json\`. Current HeroSSID-issued JWTs preserve a legacy \`vc.context\` property rather than standards-required \`vc.@context\`, so claiming standard \`jwt_vc_json\` would be wrong. The only supported DCQL query requests a single full-disclosure holder-bound \`herossid_vc_jwt\` with id \`herossid_vc\`. The format extension is only meaningful to a wallet that implements it.
- The holder independently pins the expected verifier \`did:key\` **and exact HTTPS callback** before calling \`TryReadSignedRequest\`. That method verifies the real Ed25519 signature, DID key id, allowed DCQL, exact destination, timing and nonce. The holder application must then visibly show **all** credential claims, who will receive them and obtain a real decision to disclose. A wallet must not treat a request's self-proclaimed verifier DID as trusted.
- After consent, \`CreateHolderResponseForm\` validates the issuer-signed original credential and holder key, signs a full-disclosure W3C-shaped \`vp+jwt\` envelope, and emits \`application/x-www-form-urlencoded\` with the OpenID4VP 1.0 \`vp_token\` JSON-object mapping \`herossid_vc\` to a one-element array and the one-use \`state\`. Send via HTTPS POST to the **pinned** response URI; no private key is transmitted. The embedded original issuer credential is not reissued or modified.
- The verifier's HTTP handler (supplied by the caller) passes the original form body to \`CheckResponseForm\` with its **own** trusted issuer snapshot, exact client ID, nonce and challenge store. It returns \`Invalid\`, \`Revoked\` or \`SignedNotListed\`, using real holder/issuer/snapshot signatures and atomic nonce consumption. No identity claims or authorization grants are returned on rejection.

For a canceled disclosure, the wallet simply does not POST. A challenge expires automatically; no negative/denial callback is implemented. An invalid response does not consume a valid challenge; a successfully accepted response consumes exactly once. Revoked results are not accepted.

## Minimal C# integration

\`\`\`csharp
// verifier process; verifierSeed remains private and verifier trusts issuerDid
string clientId = "decentralized_identifier:" + verifierDid;
var challenge = verifierStore.Issue(verifierTenant, clientId, issuerDid);
var callback = new Uri("https://verifier.example/openid4vp/response");
string signedRequest = OpenId4VpDirectPost.CreateSignedRequest(
    challenge, verifierDid, verifierSeed, callback, TimeProvider.System);

// holder process (only after independently pinning verifierDid AND callback):
if (!OpenId4VpDirectPost.TryReadSignedRequest(
        signedRequest, trustedVerifierDid, pinnedCallback, TimeProvider.System, out var request))
    throw new InvalidOperationException("Untrusted request");
// Display every credential claim; obtain informed full-disclosure consent here.
string formBody = OpenId4VpDirectPost.CreateHolderResponseForm(
    signedRequest, trustedVerifierDid, pinnedCallback,
    originalIssuerJwt, holderDid, holderSeed, TimeProvider.System);
// POST formBody to pinnedCallback with Content-Type: application/x-www-form-urlencoded.

// verifier callback: obtain state/nonce from its OWN session, not from an untrusted token.
var verdict = OpenId4VpDirectPost.CheckResponseForm(
    receivedFormBody, freshIssuerSignedSnapshot, verifierTenant,
    clientId, challenge.Nonce, verifierStore, TimeProvider.System);
\`\`\`

## Explicit security and interoperability limits

\`SignedNotListed\` only indicates that genuine signatures and a fresh, signed *HeroSSID* revocation snapshot were checked; a credential absent from the snapshot may have been revoked after publication (maximum snapshot age 60 seconds). It is not business authorization, issuer registration, reality-based identity proof, proof of wallet UI consent or a W3C status-list receipt. The issuer policy is pinned by the verifier, not by the holder's JSON. No public DID resolver, OAuth authorization UI, authenticated callback session, standalone HTTP app, independent wallet/conformance harness or production deployment is provided. A real integrator must authenticate sessions, rate-limit the callback, bind posted state to the correct pending request, suppress rejected data, and get a separate third-party wallet test before claiming interop. No database schema or production state is modified by this library.
