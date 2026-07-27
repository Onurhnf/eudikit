# @eudikit/core

The framework-agnostic verifier engine: build an OpenID4VP request, hand the wallet's response
back, get a verified result — inside your own Node process.

> **Pre-release skeleton — not production ready, not published.** The public surface below is
> stable, but every entry point currently throws
> `EudikitError('INTERNAL', '… not implemented yet …')`. Exactly one module has real behaviour:
> `src/mdoc/session-transcript.ts`.

## What is actually implemented

`src/mdoc/session-transcript.ts` + `src/mdoc/cbor.ts` — deterministic CBOR construction of
`OpenID4VPHandover`, `OpenID4VPDCAPIHandover` and `SessionTranscript`.

This is first on purpose. `DeviceSigned.deviceAuth` is a signature over these exact bytes, so if
the encoding is off by one byte the device signature never validates and every later claim about
"verified" is meaningless. The tests in `test/session-transcript.test.ts` assert byte equality
against the hex vectors in **OpenID4VP 1.0 Final, Appendix B.2.6**, and additionally against
`@owf/mdoc`'s own builder.

The CBOR encoder is ours, ~90 dependency-free lines, deliberately not `cbor-x`: these structures
get hashed, so the encoding must be deterministic, and `cbor-x` ships an `eval`-based decoder that
breaks under strict CSP and on some edge runtimes.

```bash
pnpm --filter @eudikit/core test
```

## Design rules this package is held to

1. **No dependency type leaks into the public API.** `@owf/mdoc`, `@openid4vc/*`, `dcql` and `jose`
   stay internal; inputs are our own types plus `Uint8Array`/PEM strings. Even `JsonWebKey` is
   avoided, because it would drag in `lib.dom` — hence our own `Jwk`.
2. **Verification happens only on the server.** The React and Expo packages are transport, never
   crypto.
3. **Strict by default.** `verified` is computed strictly; `diagnostics: Check[]` is returned in
   full in *every* mode and every outcome, and `result.policy` records which trust mode produced
   the result, so a permissive result can never masquerade as a strict one.
4. **`profile` is mandatory.** There is no global default, so the December 2026 "do we change the
   default and break everyone?" problem never arises.
5. **Wallet-class failures do not throw.** `verify()` returns `{ verified: false, error, diagnostics }`;
   throwing is reserved for programming and configuration errors.

## Runtime

Node ≥ 20.19. Edge/worker compatibility is **not** claimed — `node:crypto` in the X.509 layer and
`cbor-x`'s `eval` in a transitive dependency are two concrete reasons to measure before claiming.

Apache-2.0. Not affiliated with the European Commission.
