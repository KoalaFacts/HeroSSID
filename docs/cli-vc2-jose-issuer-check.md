# Verify a direct VCDM 2.0 / VC-JOSE issuer with HeroSSID CLI

This opt-in .NET 10 command verifies a genuine **issuer-signed direct VC Data
Model 2.0 JSON credential** in compact JWS form. It uses the restricted
`vc+jwt` profile of [W3C VC Data Model 2.0](https://www.w3.org/TR/vc-data-model/)
and [VC-JOSE-COSE](https://www.w3.org/TR/vc-jose-cose/), with real Ed25519
signatures over the direct JSON payload. It does **not** process JSON-LD or
claim general VCDM conformance or third-party Wallet interoperability.

```sh
dotnet run --project src/Cli/HeroSSID.Cli -- credential verify-vc2-issuer \
  --jwt-file ./original-direct-vc2.jwt \
  --trusted-issuer 'did:key:z6Mk...' \
  --holder 'did:key:z6Mk...' \
  --credential-type MembershipCredential \
  --context https://issuer.example/contexts/membership/v2
```

All four pins are **independently configured by the verifier**, not taken from
the untrusted JWT. The supplied file must be the original unchanged compact
JWS (maximum 65,536 bytes, UTF-8; a trailing newline is tolerated). Successful
verification requires the issuer's genuine Ed25519 signature, the `vc+jwt`
JOSE header, a direct `@context` with the standard VC 2.0 entry and exact
approved context, pinned type, issuer, holder `credentialSubject.id`,
validity window and the strictly bounded six-member direct VC2 payload
profile. Signed additional fields such as `credentialStatus`, `proof`,
`evidence` and `credentialSchema` are **rejected**, not silently ignored.

Exit code **0** means only that an issuer-controlled Ed25519 key genuinely
signed the **time-valid** direct VC2 statement matching the verifier's exact
pins. The command does not print the JWT or subject claims. Invalid, expired,
tampered, missing, oversized, malformed or wrong-policy credentials exit
**nonzero without releasing claims**. An authentic VC1.1 nested `vc` JWT
cannot be supplied as VC2. The existing `credential verify-issuer` command
remains a **separate VC1.1 `jwt_vc_json`** verifier.

Neither CLI command checks holder private-key control, presentation
request/challenge binding, explicit human consent, revocation/status,
real-life identity, legal-entity enrolment, Agent delegation or business
authorization. A correctly signed claim is **not** a proof of its truth or a
right to perform a business action. The verifier is responsible for
independent issuer enrollment and vocabulary governance.

The direct-JOSE library profile does not fetch or expand JSON-LD contexts:
[implementation constraints](vcdm20-jose-profile.md). No independent wallet
exchange, formal conformance suite, hosted OpenID4VC endpoint or release is
claimed. For the other independently verified CLI format, see
[VC1.1 issuer verification](cli-vc11-issuer-check.md).
