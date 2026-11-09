# Direct VC2 did:key: offline verifier-owned one-use session

This is the **receiving/verifying half** of the existing [holder CLI](cli-vc2-didkey-holder.md) and [issuer CLI](cli-vc2-didkey-issuer-issue.md). A verifier with its own genuine Ed25519 `did:key` signing seed can issue a policy-bound request, keep local protected challenge state and later authenticate one full-disclosure holder VP. It preserves the **original issuer's** direct VC2 `vc+jwt` signature separately from the **holder's** `vp+jwt` signature.

## Create a request (verifier controls this operation)

Generate and independently enroll three different Ed25519 `did:key` identities for the issuer, holder and verifier. The verifier independently selects and approves the issuer, credential type, HTTPS vocabulary, exact canonical HTTPS audience and nonempty tenant GUID. Do **not** learn these trust pins from the holder VP or issuer-supplied links.

```sh
dotnet run --project src/Cli/HeroSSID.Cli -- credential request-vc2-didkey \
  --verifier-did 'did:key:zPINNED_VERIFIER' \
  --tenant-id 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' \
  --audience 'https://verifier.example/credential-check' \
  --trusted-issuer 'did:key:zPINNED_ISSUER' \
  --credential-type 'MembershipCredential' \
  --context 'https://issuer.example/vocab/membership/v1' \
  --output-request-file ./signed-request.jwt \
  --session-file ./private-session.json \
  --lifetime-seconds 120 < /secure/verifier-seed.hex
```

The placeholders are **not** real DIDs. The seed file contains a 32-byte Ed25519 seed encoded as hex plus a newline, supplied **only through redirected stdin**, never argv or a repository. The CLI signs a real policy-bound request and writes both files **create-new**; the private session has owner-only permissions on Unix. It retains a SHA-256 digest of the exact original signed request, issuer policy, nonce, audience, tenant and expiry. Never copy or disclose the session file to the holder.

The holder independently pins the signed request's real verifier DID and exact issuer, type, context and recipient, then uses [`credential present-vc2-didkey`](cli-vc2-didkey-holder.md) to sign a genuine full-disclosure VP. The calling holder UI must **display all claims** and obtain deliberate approval; `--ack-full-disclosure` is just an unverified assertion by the calling program, not consent evidence.

## Check a presentation (verifier controls this operation)

```sh
dotnet run --project src/Cli/HeroSSID.Cli -- credential verify-vc2-didkey-vp \
  --verifier-did 'did:key:zPINNED_VERIFIER' \
  --tenant-id 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' \
  --audience 'https://verifier.example/credential-check' \
  --trusted-issuer 'did:key:zPINNED_ISSUER' \
  --credential-type 'MembershipCredential' \
  --context 'https://issuer.example/vocab/membership/v1' \
  --request-jwt-file ./signed-request.jwt \
  --session-file ./private-session.json \
  --presentation-jwt-file ./holder-vp.jwt
```

This verifies the **original**, exact verifier Ed25519-signed request and independently stored hash, pinned issuer and context, original issuer-signed VC2 JWT, holder's own Ed25519 VP signature, request hash embedded in the VP, type, audience, nonce and validity window. It then atomically renames the verifier-owned local challenge to `.used`, so a replay or simultaneous second verifier fails. It never prints claims. Failed signature/pin checks do not intentionally consume the challenge; an otherwise valid signed VP uses the nonce once, even if subsequent policy checks fail.

This is a **single local filesystem** profile. Do not use NFS, restored backups, untrusted directory writers or multiple machines as a substitute for a genuinely shared atomic challenge store. Expired sessions require a **new** verifier request; never resurrect a consumed nonce.

**Security boundary:** Successful verification is only `SignedButStatusUnchecked`: authentic issuer assertion + proof that a key signed the holder VP + one-use challenge. It is **not** issuer live status, complete non-revocation, real-world identity, independently verified human consent, receiving-system authorization, formal VCDM/JSON-LD conformance, OpenID4VP compatibility or third-party wallet interoperability. The receiving business must make a separate authorization and incident decision.
