# @eudikit/react

Browser transport for eudikit: `useVerification()` (headless) and `<AgeGate/>` (the widget on top
of it).

> **Pre-release — not published yet.**

This package **never verifies anything**. It calls `navigator.credentials.get()`, falls back to a
QR code when the Digital Credentials API is unavailable, polls the server for the result, and
renders. All cryptography lives in `@eudikit/core` on the server — client-side verification would
be no verification at all. Nothing here imports `@eudikit/core` at runtime, only its types, so no
verifier code can end up in a browser bundle.

```tsx
'use client'
import { AgeGate } from '@eudikit/react'

export default function Page() {
  return (
    <AgeGate endpoint="/api/eudikit" request="age" channels={['qr']}>
      <p>Adults only.</p>
    </AgeGate>
  )
}
```

The widget is unstyled on purpose: it renders semantic HTML with a `className` on the root, a
`data-eudikit-status` attribute to style against, `role="status"` for the live status line and
`role="alert"` for failures. For a different design, pass `fallback` — a node, or a function of
the hook state — and keep the wiring.

## The hook

```tsx
const { status, start, cancel, channel, qrPayload, deepLink, claims, error } = useVerification({
  endpoint: '/api/eudikit',   // where createFetchHandler / createNextHandler is mounted
  request: 'age',             // a name registered in that handler
  channels: ['dc-api', 'qr'], // preference order (default)
  pollIntervalMs: 1500,       // base interval; backs off to 8 s
})
```

`start()` **must be called from a user gesture** — the Digital Credentials API consumes transient
activation. It reaches `navigator.credentials.get()` through its own promise chain, with a single
server round trip and no timers in between, so the activation is still valid when the call lands.

What the package owns so that integrators do not have to:

- the `typeof DigitalCredential` guard and `userAgentAllowsProtocol()` negotiation — checked
  before the request is created and again against the protocol the server actually produced;
- falling back to the next channel when the DC API is missing, refuses the call, or the wallet
  was never invoked (`wallet_unavailable`), and when the server does not serve a channel for that
  request;
- mapping `NotAllowedError` onto the honest, deliberately combined
  `USER_DECLINED_OR_NO_CREDENTIAL` — and *not* silently switching channels after the user has
  answered a picker;
- polling that backs off, pauses while the tab is hidden, stops at the request's `expiresAt`, and
  rides out transport failures;
- `cancel()`, which aborts the in-flight call and the poll loop.

`deepLink` is exposed, never navigated to: a hook that changes `location` out from under a click
cannot be composed with. Render it as a link.

`diagnostics` never reaches the client by default; exposing it is a server-side opt-in
(`exposeDiagnostics` on the core handler). What arrives here is `{ code, message }`, where the
message is written for developers — `<AgeGate/>` shows its own copy, keyed by code.

## QR rendering

`<QrCode value={qrPayload} />` encodes with [`uqr`](https://github.com/unjs/uqr) (dependency-free)
and renders the module matrix as ordinary SVG elements — no canvas, no
`dangerouslySetInnerHTML`, no `eval`. It works under a strict Content-Security-Policy and renders
on the server.

## Today's EU AV wallet

The AV wallet answers `openid4vp-v1-*` over the deep-link and QR channels only; over the Digital
Credentials API it speaks a protocol this release does not implement. Use `channels: ['qr']` (or
`['deep-link', 'qr']`) against it, which also needs a publicly reachable HTTPS base URL on the
server. The DC API path is for Google Wallet and the December 2026 EUDI wallets.

Apache-2.0. Not affiliated with the European Commission.
