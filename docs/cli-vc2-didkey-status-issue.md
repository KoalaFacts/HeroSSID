# Offline issuer-signed VC2 did:key private status for Agent credentials

An **issuer operator without the .NET SDK** can now publish one authentic,
short-lived revocation observation for its original direct VC2 `vc+jwt`
credentials. This closes the last issuer-side CLI input required by the
[offline Agent holder and verifier journey](cli-vc2-agent-scope-vp-status.md).
The new `credential issue-vc2-didkey-status` signs using the *issuer's own*
Ed25519 seed read from redirected stdin, not a holder key or a verifier key.

The issuer's trusted DID is not learned from a wallet or from a revocation
manifest. Independently enroll the issuer DID at the verifier before relying on
this snapshot. The issuer maintains the **complete authoritative set** of
revoked original JWTs, records the actual UTC observation time *before*
collecting that set, and signs within 60 seconds of that instant.

## Issuer procedure

Prepare a UTF-8/ASCII file of **exact unchanged original revoked direct VC2
JWTs**, one compact JWT per line, with no quotes or whitespace. For no revoked
credentials, provide an **existing empty file**. The reader enforces a 4 MiB
file cap, at most 256 entries and 65,536 characters per original JWT. Every
listed JWT must have an authentic signature from this exact issuer; a
forgery or a foreign-issuer JWT aborts the export.

Use your current observed UTC instant in round-trip format for
`--observed-at`, not the example below, and only after the issuer's source
was accurately observed. Example command syntax:

```sh
dotnet run --project src/Cli/HeroSSID.Cli -- credential issue-vc2-didkey-status \
  --issuer-did 'did:key:zISSUER_FROM_OPERATOR_CONFIGURATION' \
  --revoked-jwt-list-file ./issuer-owned-revoked-originals.txt \
  --observed-at '2026-11-09T03:20:00.0000000+00:00' \
  --output-jwt-file ./issuer-status.jwt < /secure/issuer-seed.hex
```

The DID shown is a placeholder, **not** a valid signing identity; the timestamp
is illustrative and must be replaced with a fresh real observation. Keep the
issuer seed out of command arguments, logs, shell history, repositories and
public files. The seed pipe accepts the same private Ed25519 seed encoding
as `issue-vc2-agent-scope`. The output is new, non-overwriting and
owner-private on Unix; an existing destination is rejected. No credential or
private key is printed by the command.

The verifier separately obtains this issuer-signed snapshot through its own
trusted operational channel and passes it as `--snapshot-file` to
[`verify-vc2-agent-scope-vp-status`](cli-vc2-agent-scope-vp-status.md),
together with its **own** minimum issuer observation time, original Agent
full-disclosure VP, exact trusted issuer, scope and one-use challenge. The
verifier cannot derive its policy from the snapshot. A no-SDK relying party can instead run the [offline VC2 did:key issuer-status verifier CLI](cli-vc2-didkey-status-verify.md) with independently pinned issuer, holder, type and context plus its own minimum observed-at cutoff. This verifies a genuine original issuer-signed VC2 before checking the same unchanged JWT digest against the signed status; it does not authenticate a holder key or release claims. The SDK can also use
`Vcdm20RevocationSnapshot.CheckWithObservationCutoff` to distinguish
`Invalid`, `Revoked` and `SignedNotListed` for an exact original VC2 JWT.

## What the signature does and does not prove

The signed snapshot has at most **60 seconds** of validity measured from the
issuer's observation timestamp. `SignedNotListed` proves only that the
authentic, still-current issuer observation omitted the exact JWT digest.
It **does not** prove the issuer's inventory was complete, that the
credential is live/unrevoked now, that an Agent controls its private key,
that a person/organisation was vetted, or that any business action is
authorized. Fail closed on outage, stale status, forged input or conflicting
local incident policy. Do not extend the 60-second validity or accept
old snapshots after an incident. The receiving application must independently
evaluate authorization, access-control, and new incident evidence.

The snapshot format is HeroSSID-private
(`herossid-vc2-revocation-snapshot+jwt`), **not** the W3C Bitstring Status
List, a standard OpenID4VP status exchange, or proof of third-party Wallet
interoperability. No production revocation service, shared-status distribution,
hosted endpoint, external audit, deployment or key custody is supplied.
