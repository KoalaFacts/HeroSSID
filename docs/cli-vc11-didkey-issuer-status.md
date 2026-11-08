# Offline VC1.1 `jwt_vc_json` issuer status — CLI

This **single-issuer private status profile** gives a non-SDK issuer operator
and a separately trusted verifier two executable .NET 10 commands. It uses
genuine Ed25519 signatures and the **unchanged original** W3C VC1.1
`jwt_vc_json` credential. The status JWT format is
`herossid-jwt-vc-json-revocations+jwt`, a **HeroSSID-private 60-second
snapshot**. It is **not** the W3C Bitstring Status List or proof of independent
Wallet interoperability.

The issuer signs what it has observed; the verifier makes its own policy
decision. A valid issuer signature and `SignedNotListed` are **not** live
non-revocation, holder private-key possession, legal identity, human consent or
business authorization.

## Issuer: publish a complete signed observation

Before creating a snapshot, the issuer must authenticate ownership of the
credential population, query its **own authoritative revocation registry** and
prepare the **complete** revoked set. The CLI cannot infer completeness, a
current registry, or authority over other organisations.

Create a private UTF-8 JSON file whose root is an array of **original compact
issuer-signed VC1.1 JWT strings**, without a trailing newline **inside** any
array element. Include all revoked credentials for this issuer and status
scope, not merely the newest change. Use `[]` only after the operator has
independently verified that the authoritative set really is empty.
A maximum of 256 **distinct** revoked JWTs and a bounded 17 MB input are
accepted. An unrelated signer, a modified/forged JWT or malformed JSON
is rejected before any status file is released. Never put these original
credential strings into logs or a public repository.

Record the exact UTC observation instant; it must still be within the 60-second
freshness window when signed. The issuer's real 32-byte Ed25519 seed is supplied
through **redirected stdin**, never as a command-line argument:

```sh
dotnet run --project src/Cli/HeroSSID.Cli -- credential issue-vc11-didkey-status \
  --issuer-did 'did:key:zREAL_ISSUER_KEY' \
  --revoked-jwts-manifest-file ./issuer-private-revoked-jwts.json \
  --observed-at '2026-11-09T00:00:00.0000000+00:00' \
  --output-snapshot-file ./issuer-status.jwt \
  < /secure/issuer-ed25519-seed.hex
```

Replace the sample observation time with the **actual current UTC observation**,
not a copied example. The command creates a new status file and will not
overwrite an existing path; on Unix it uses owner-only `0600` creation mode.
The signing seed is never written to the snapshot. Protect and rotate original
credentials and issuer seed through your own secure lifecycle controls.
The snapshot is an independently verifiable signed digest set, **not** a
credential or identity record.

## Verifier: pin the credential and status issuer independently

The relying party must obtain its original unchanged issuer-signed VC1.1 JWT
and a **separately supplied** issuer status JWT. Enrol the issuer's `did:key`,
signed descriptive issuer name, exact signed HTTPS credential ID, holder DID,
credential type and HTTPS vocabulary independently. **Do not** learn pins or
the observation cutoff from the JWT, Wallet or status payload.

```sh
dotnet run --project src/Cli/HeroSSID.Cli -- credential verify-vc11-didkey-pinned-status \
  --jwt-file ./original-issuer-credential.jwt \
  --snapshot-file ./issuer-status.jwt \
  --trusted-issuer 'did:key:zREAL_ISSUER_KEY' \
  --issuer-name 'Independently approved issuer name' \
  --credential-id 'https://issuer.example/credentials/42' \
  --holder 'did:key:zEXPECTED_HOLDER_KEY' \
  --credential-type 'MembershipCredential' \
  --context 'https://issuer.example/vocab/member' \
  --minimum-observed-at '2026-11-09T00:00:00.0000000+00:00'
```

Choose a **real, verifier-controlled, UTC incident cutoff** that the issuer's
authenticated observation must meet. A future cutoff, stale or expired
observation, wrong issuer, tampered signature, revoked original credential,
altered holder or issuer metadata, or missing input fails closed with exit 1.
A matching genuine issuer signature and authentic status whose complete set
does **not** list this exact original JWT returns exit 0, with **no subject
claims printed**. The verifier reads the credential exactly once for both
credential-signature and status-digest validation, preventing a file-swap
between checks.

Signed absence never establishes the issuer's **completeness** or that status
has not changed since observation. Integrators must independently assess
source completeness, delivery, emergency denial and business policy. This
issuer-only status check does **not** verify any holder presentation, consent,
person or organisation enrolment, Agent delegation or legal authority; for a
separate holder-signed one-use VP flow see
[offline verifier session](cli-vc11-offline-verifier-session.md).
