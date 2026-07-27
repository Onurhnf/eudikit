# @eudikit/expo

React Native / Expo transport for eudikit.

> **Pre-release skeleton — not published.** The public surface is stable; every export throws
> today.

## v1 scope: deep link + QR only

This is a decision, not an omission.

The native Android path — `androidx.credentials` / Credential Manager — requires the
`org-iso-mdoc` protocol (ISO 18013-7 Annex C, with HPKE per RFC 9180), which v1 does not
implement. Rather than ship a `nativeRequest` that quietly fails, v1 keeps the surface and tells
the truth: `getCapabilities()` returns `nativeRequest: false` with `reason: 'NATIVE_PATH_V1_1'`.
The native path arrives in v1.1 together with `@eudikit/iso-18013-7`.

`strategy: 'auto'` therefore resolves to **deep link → (no wallet installed) → QR** on both
platforms, which is also the flow that actually works with today's EU AV wallet.

## The origin trap

Android app origins are not URLs. The server's `expectedOrigins` needs
`android:apk-key-hash:<base64url-nopad-sha256>`, and **debug and release builds produce different
values** — list both, or the release build gets silently rejected. `getAppOrigin()` exists so that
this value is computed rather than guessed.

## Layer boundary

This package is transport. `requestCredential()` hands the server's request to the wallet
unchanged and carries the wallet's response back unchanged. Verification happens on the server, in
`@eudikit/core`. Anything this layer rewrites is something an attacker could rewrite too.

Apache-2.0. Not affiliated with the European Commission.
