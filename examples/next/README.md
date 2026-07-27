# examples/next — placeholder

A working Next.js integration lands with the implementation phase, not with the skeleton: a real
Next app pulls a few hundred megabytes of `node_modules` into a repository whose engine currently
throws on every call. There is nothing to demo yet.

The example will cover the two end-to-end flows:

- **Digital Credentials API on localhost** — for Google Wallet and the December 2026 EUDI
  wallets.
- **Deep link / QR + `direct_post`** — the flow that works with today's EU AV wallet, over a
  public HTTPS tunnel.

## Read this warning before you build a demo

Today's AV wallet speaks **only `org-iso-mdoc`** over the DC API. An `openid4vp-v1-*` request
shows *no credential at all* in the picker and returns no error — the demo simply looks broken
with nothing to debug. That is why `profile: 'av'` combined with `channel: 'dc-api'` throws
`CHANNEL_PROFILE_MISMATCH` instead of politely trying: the trap is built into the API so nobody
has to rediscover it at demo time.

For a demo against the real AV wallet, use the deep link/QR flow and read
[`../../testbed/README.md`](../../testbed/README.md) first.

## What this example will show when it is written

1. `lib/verifier.ts` — `createVerifier({ profile, session, expectedOrigins, trust })`.
2. `app/api/eudikit/[...eudikit]/route.ts` — one line: `export const { GET, POST } = createNextHandler(...)`.
3. `app/age/page.tsx` — `<AgeGate/>`, or `useVerification()` for a custom UI.
