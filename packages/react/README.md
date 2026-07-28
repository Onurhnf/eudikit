# @eudikit/react

Browser transport for eudikit: `useVerification()` — the headless hook that is the primary API —
and `<AgeGate/>`, a small ready-made widget built on top of it.

> **Pre-release — not published yet.**

This package **never verifies anything**. It calls `navigator.credentials.get()`, falls back to a
QR code when the Digital Credentials API is unavailable, polls the server for the result, and
renders. All cryptography lives in `@eudikit/core` on the server — client-side verification would
be no verification at all. Nothing here imports `@eudikit/core` at runtime, only its types, so no
verifier code can end up in a browser bundle.

## The hook

```tsx
const { status, start, cancel, channel, qrPayload, deepLink, claims, error } = useVerification({
  endpoint: '/api/eudikit',   // where createFetchHandler / createNextHandler is mounted
  request: 'age',             // a name registered in that handler
  channels: ['dc-api', 'qr'], // preference order (default)
  pollIntervalMs: 1500,       // base interval; backs off to 8 s
})
```

The hook carries **no copy and no locale**: `status` is a machine-readable state
(`idle | creating | awaiting_wallet | polling | verified | failed | expired`) and `error` is a
stable `{ code, message }` where the message is written for developers, not for screens. Turning
codes into words is a UI concern — yours, or `<AgeGate/>`'s below.

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
(`exposeDiagnostics` on the core handler).

## Your own UI: the render prop

When `children` is a function, `<AgeGate/>` renders nothing of its own: the function receives
the hook state plus the resolved label catalog and the gate `decision`, and owns every status,
`verified` included. It is `useVerification()` with the labels and the decision wired in. Gate
on `decision`, not on `status` — `verified` says the presentation is authentic, not that the
answer is the one you need (see "Verified is not the same as allowed" below).

```tsx
'use client'
import { AgeGate, getErrorText, VerificationQr } from '@eudikit/react'

<AgeGate endpoint="/api/eudikit" locale="de">
  {({ decision, start, qrPayload, error, labels }) =>
    decision === 'passed' ? (
      <p>Willkommen.</p>
    ) : decision === 'declined' ? (
      <p>{labels.declined}</p>
    ) : (
      <div>
        <button type="button" onClick={() => void start()}>{labels.trigger}</button>
        {qrPayload !== null && <VerificationQr payload={qrPayload} label={labels.qrLabel} />}
        {error !== null && <p role="alert">{getErrorText(labels, error.code)}</p>}
      </div>
    )
  }
</AgeGate>
```

`fallback` is the smaller version of the same idea: also a node or a function of the same state,
but it only replaces the panel while the gate is not passed — the gate behaviour stays, and
`children` render once the decision is `passed`. The function form can branch on `decision` to
give the `declined` state its own copy; a plain node shows the same content either way.

## Quick start: `<AgeGate/>`

The day-zero path — one component, semantic HTML, no styling opinions:

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

Children stay unrendered until the presentation verifies **and** its answer passes the gate's
`decide` policy — `claims?.ageOver === true` unless you override it (next section). The default
panel renders the start button, the QR code with a same-device wallet link, a `role="status"`
live region and a `role="alert"` failure line. Failures are shown from a curated list of
user-facing error codes; anything else — configuration mistakes, internals — renders the
catalog's `generic` line while `onError` still receives the real `code`, which is also logged
to the console in development.

## Verified is not the same as allowed

`status === 'verified'` means the presentation is *authentic*: issuer signature, value digests,
device binding and session binding all checked out, and the credential answers the query that
was asked. It does **not** mean the answer is the one your page needs. A wallet can truthfully
present `age_over_18: false` — that presentation verifies, and a gate keyed on `verified` alone
would open for an authentic "no". Authenticity and content are separate checks, and skipping
either one is an open door.

How the two are split across this package:

- **`useVerification()` never decides.** It reports `status` (was the presentation verified?)
  and `claims` (what did it say?). A UI built directly on the hook reads `claims` and applies
  its own policy.
- **`<AgeGate/>` decides through the `decide` prop.** The default policy is
  `claims?.ageOver === true`, matching what the `age` preset produces. Verified with a negative
  decision is the **`declined`** state: `children` stay unrendered, the neutral `declined`
  catalog line shows in the status region, `data-state` becomes `declined` — and `error` stays
  `null`, because nothing failed.
- **Render functions see the split explicitly**: the state they receive carries
  `decision: 'pending' | 'passed' | 'declined'` next to `status`.

Any other policy goes through `decide` — for example gating on the `country` preset's claims:

```tsx
<AgeGate
  endpoint="/api/eudikit"
  request="country"
  decide={(claims) => Array.isArray(claims?.countries) && claims.countries.includes('DE')}
>
  <p>Willkommen.</p>
</AgeGate>
```

## Styling with data attributes

The widget ships no CSS and no theme system. Every meaningful element is addressable instead:

| attribute | where | values |
| --- | --- | --- |
| `data-part` | every element | `root`, `trigger`, `panel`, `qr`, `link`, `hint`, `status`, `error`, `cancel` |
| `data-state` | the root and every part | `idle`, `creating`, `awaiting_wallet`, `polling`, `verified`, `failed`, `expired`, `declined` |
| `data-channel` | the root, once a channel is chosen | `dc-api`, `qr`, `deep-link` |

`declined` is the gate outcome, not a hook status: it replaces `verified` on every part when an
authentic answer does not pass `decide`, so CSS keyed on the verified state never reaches an
authentic "no". Style it neutrally — it is an outcome, not an error, and the panel keeps
`role="alert"` for real failures.

Plain CSS reaches any moment of the flow:

```css
[data-part='trigger'] {
  padding: 0.75rem 1.5rem;
}
[data-part='trigger'][data-state='polling'] {
  opacity: 0.6;
  cursor: progress;
}
[data-part='root'][data-channel='qr'] [data-part='qr'] {
  margin-block: 1rem;
}
[data-part='error'] {
  color: #b91c1c;
}
[data-part='status'][data-state='declined'] {
  border-inline-start: 3px solid currentColor;
  padding-inline-start: 0.75rem;
}
```

The root also keeps the `data-eudikit-status` attribute from earlier releases.

## Localisation

Catalogs ship for English, Turkish and German — the languages we could check ourselves.
**Translations are a great first contribution.**

`locale` picks a catalog; `labels` overrides any field on top of it. Resolution is field by
field: `labels` > `locale` > English.

```tsx
<AgeGate endpoint="/api/eudikit" locale="de" labels={{ trigger: 'Altersnachweis starten' }}>
```

The catalogs are plain objects at `@eudikit/react/locales` (usable in server components), and
`getLabels(locale?, overrides?)` is the pure resolver behind the props — a full
`EudikitReactLabels` object covers every string the widget renders, `aria` labels included, so a
hand-written catalog plugs straight into `labels`:

```ts
import { de } from '@eudikit/react/locales'
```

The widget never reads `navigator.language`: a server-rendered page would hydrate with different
text than it shipped. Pass the locale your page has already negotiated, and the root element
carries it as `lang` so assistive technology switches pronunciation with the copy.

## QR rendering

`<VerificationQr payload={qrPayload} />` (and its older alias `<QrCode value={…} />`) encodes
with [`uqr`](https://github.com/unjs/uqr) (dependency-free) and renders the module matrix as
ordinary SVG elements — no canvas, no `dangerouslySetInnerHTML`, no `eval`. It works under a
strict Content-Security-Policy and renders on the server, and it forwards `data-*` attributes
for the styling contract above.

## Today's EU AV wallet

The AV wallet answers `openid4vp-v1-*` over the deep-link and QR channels only; over the Digital
Credentials API it speaks a protocol this release does not implement. Use `channels: ['qr']` (or
`['deep-link', 'qr']`) against it, which also needs a publicly reachable HTTPS base URL on the
server. The DC API path is for Google Wallet and the December 2026 EUDI wallets.

Apache-2.0. Not affiliated with the European Commission.
