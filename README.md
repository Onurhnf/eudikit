# eudikit

**A relying-party SDK for the EU Digital Identity (EUDI) and Age Verification (AV) wallet
ecosystem — a library, not a service.** `npm install @eudikit/core` and your Node/Next.js
application can ask a wallet to prove *"over 18"*, *"resident of X"*, or (later) a full
identity, then verify the answer **inside your own process**: mdoc/SD-JWT signature checks,
ETSI TS 119 612 trusted-list lookup, nonce/audience/session binding, DCQL claim-level
post-validation. No separate container, no hosted API, no tenant. The European Commission's
own reference verifier is a Kotlin microservice you deploy next to your app; eudikit's whole
point is that the verification runs where your code runs.

## Status: pre-release — NOT production ready

The mdoc path works end to end — against the OpenID4VP 1.0 test vectors, a real EU trusted
list, and **a real wallet on a real phone**: the EU Age Verification wallet presented a
Proof-of-Age attestation over a deep link and this SDK verified it, device signature and
trusted-list membership included. Nothing is published to npm yet, and the eudi profile
(December 2026 wallets) has not met a live counterparty. Do not use it to make a real
access-control decision.

| Package | State |
|---|---|
| `@eudikit/core` | request production, `direct_post` and DC API response handling, the full mdoc verification chain, DCQL post-validation, the AV trusted list, session adapters, HTTP handlers. SD-JWT VC verification still throws. |
| `@eudikit/react` | `useVerification()` and `<AgeGate/>`: DC API negotiation, QR fallback, polling |
| `@eudikit/expo` | stub — v1 scope is deep-link/QR only, native path deferred to v1.1 |
| `examples/next` | a working age gate: [`examples/next`](examples/next) |

## What v1 will and will not do

**In:** OpenID4VP 1.0 Final, DC API (`openid4vp-v1-unsigned` / `-signed`), QR + deep-link with
`direct_post` and `direct_post.jwt`, mdoc (`mso_mdoc`) and SD-JWT VC (`dc+sd-jwt`), AV trusted
list, strict-by-default verification with a full `diagnostics` report in every mode.

**Out (v1):** `org-iso-mdoc` / ISO 18013-7 HPKE (reserved as a `ProtocolAdapter`, v1.1), ZKP,
`transaction_data`, OpenID4VCI / issuance, federation and DID client-id prefixes, and any
policy engine — eudikit returns verified data, your application applies the business rule.

> ⚠️ **Wallet reality check.** Today's EU AV wallet speaks only `org-iso-mdoc` over the Digital
> Credentials API, so the DC API path in this SDK does **not** work with it — that path targets
> Google Wallet and the December 2026 EUDI wallets, plus localhost developer experience. The
> flow that works with the AV wallet today is deep-link/QR + `direct_post`, which needs a
> publicly reachable HTTPS URL. The SDK refuses the broken combination loudly instead of
> failing silently.

## Development

```bash
pnpm install && pnpm build && pnpm test
```

Node ≥ 20.19. Edge/worker compatibility is deliberately **not** claimed — it will be measured
before it is advertised.

## Licence and affiliation

Apache-2.0 — see [LICENSE](LICENSE).

**Not affiliated with, endorsed by, or connected to the European Commission or the European
Union.** "EUDI", "EUDI Wallet" and related names are used only to describe the specifications
and reference implementations this project interoperates with.
