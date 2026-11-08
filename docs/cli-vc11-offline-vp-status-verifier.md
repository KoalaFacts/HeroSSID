# Offline VC1.1 one-use VP with signed issuer-status observation

The .NET 10 verifier CLI can now make **one combined cryptographic decision**:
it checks the original issuer-signed `jwt_vc_json` inside the genuine holder-signed
`vp+jwt`, the verifier's own authentic signed request, its locally persisted
one-use challenge, and a **separately obtained genuine same-issuer 60-second
private revocation snapshot** against the verifier's earliest acceptable UTC
observation instant. The CLI never releases credential claims.

This is a HeroSSID-private offline, single-local-filesystem profile, **not**
standard W3C Bitstring Status List, current/live non-revocation, general
OpenID4VP, third-party Wallet interoperability, identity proof, actual
human consent or business authorization. Wallets only hold and present;
the issuer signs the original statement and its own status observation;
the holder separately proves Ed25519 key control; the verifier owns trust
pins, challenge and business authorization decisions.

## Three-party operation

1. An authorised issuer signs a real VC1.1 JWT via
   [issuer CLI](cli-vc11-didkey-issuer-issue.md), and signs an independently
   observed complete revoked-credential set via
   [status CLI](cli-vc11-didkey-issuer-status.md).
   Authenticity does not establish registry completeness.
2. The verifier signs a bounded request and first stores its private one-use
   session state using
   [request-vc11-didkey](cli-vc11-offline-verifier-session.md). Keep the
   request unmodified and the session state private on one trusted local host.
3. The holder authenticates the verifier and issuer independently, inspects
   all claims, and creates a holder-signed VP via
   [present-vc11-didkey](cli-vc11-didkey-holder-presentation.md).
   Its CLI acknowledgement is not proof of human consent.
4. The verifier obtains an original issuer snapshot independently of the
   holder and runs, replacing these placeholders with approved pins:

```sh
dotnet run --project src/Cli/HeroSSID.Cli -- credential verify-vc11-didkey-vp-status \
  --verifier-did 'did:key:zVERIFIER_PIN' \
  --tenant-id '52bb1e4a-f419-4e13-9e12-a539bed81f02' \
  --audience 'decentralized_identifier:did:key:zVERIFIER_PIN' \
  --trusted-issuer 'did:key:zISSUER_PIN' \
  --credential-type 'MembershipCredential' \
  --context 'https://issuer.example/vocab/membership' \
  --request-jwt-file ./signed-request.jwt \
  --session-file ./private-challenge.json \
  --presentation-jwt-file ./holder-vp.jwt \
  --snapshot-file ./issuer-status.jwt \
  --minimum-observed-at '2026-11-09T00:00:00.0000000+00:00'
```

Set the cutoff to an **actual, independently chosen UTC** observation floor,
not the example or a time supplied by the wallet. Accept exit status `0` only
when all checks pass. It means original issuer provenance, holder private-key
control, verifier-bound one-use challenge, and a signed `NotListed` observation,
**not live non-revocation**. Even an authenticated complete signed snapshot can
be outdated or an incomplete issuer export; applications must still enforce
their business trust and authorisation policy.

The session is atomically moved from `private-challenge.json` to
`private-challenge.json.used` once a genuine holder VP has been checked,
**before** evaluating the issuer snapshot. Revoked, forged, expired and
pre-incident status supplied with a valid holder proof cannot retry the
same nonce, while a forged holder VP or impossible future cutoff cannot consume
a valid session. Keep the spent marker and protect the local filesystem.
This is NOT a distributed replay store and MUST NOT be used on NFS, shared
volumes, or after restoring spent challenges from backup. Use the separate
transactional challenge-store implementation for multi-instance services.

No production keys, hosted endpoints, databases, migrations, packages or
deployment are involved in this offline command.
