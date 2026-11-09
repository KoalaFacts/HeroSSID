# Offline VC2 did:key issuer-signature + private status verifier CLI

A relying party without an SDK can independently verify the **original**
issuer-signed VCDM 2.0 direct `vc+jwt` from
[`issue-vc2-didkey`](cli-vc2-didkey-issuer-issue.md) against an
**independently enrolled** Ed25519 `did:key`, exact holder DID, credential type
and versioned HTTPS context, and also authenticate the **same issuer's**
[short-lived private status JWT](cli-vc2-didkey-status-issue.md). This
`credential verify-vc2-didkey-status` operation does not print claims,
modify files, consult a database, or authenticate holder key possession.

The verifier must obtain the original credential and issuer status over
appropriate independent operational channels. Both are required as complete
compact JWT files and are read with strict size bounds. The original
credential is authenticated once and its *same exact string* is used for
the signed status digest check; changing or reserializing that JWT changes
the digest and invalidates the observation. The verifier supplies all policy
pins independently; neither JWT can enroll an issuer or substitute a context.

## Example verifier command

For **fresh real UTC timestamps**, substitute an independently authorized
issuer DID and holder DID, an actual issuer-created direct VC2 credential and
private status file, and the verifier's earliest acceptable issuer observation.
The values below are placeholders and not valid trust anchors:

```sh
dotnet run --project src/Cli/HeroSSID.Cli -- credential verify-vc2-didkey-status \
  --jwt-file ./received-original-vc2.jwt \
  --snapshot-file ./issuer-status.jwt \
  --trusted-issuer 'did:key:zPREAPPROVED_ISSUER' \
  --holder 'did:key:zEXPECTED_HOLDER' \
  --credential-type 'RoleCredential' \
  --context 'https://issuer.example/contexts/role/v1' \
  --minimum-observed-at '2026-11-09T05:00:00.0000000+00:00'
```

The timestamp is **illustrative**, not current. Pass an actual verifier-owned,
UTC round-trip lower bound selected from incident and operational policy.
The command returns exit code **0** only when the genuine original issuer VC2
signature, *all* independent pins, credential validity and a genuine
same-issuer status **observed no earlier than the bound and no older than
60 seconds** jointly pass, and the JWT digest is not listed as revoked.
Missing, stale, pre-incident, forged, mismatched, revoked or malformed artifacts
produce a nonzero exit code and no claims. It does not fall back to legacy
nested `vc` JWT or VC1.1 `jwt_vc_json`.

**Trust limits:** `SignedNotListed` only means the digest was absent from one
authentic, short-lived issuer observation. It cannot prove inventory completeness,
live non-revocation, possession of the holder's private key, consent, human or
organisation identity, Agent delegation, or business authorization. The verifier
must apply separate holder-proof and relying-party authorization policies when
those are required. The snapshot format is HeroSSID-private, **not** W3C
Bitstring Status List; this is not a third-party Wallet/OpenID4VP conformance
claim, hosted service, production publication or external security audit.
