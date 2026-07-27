# examples/next — an age gate against the EU AV wallet

A complete Next.js integration in three files:

| File | What it does |
|---|---|
| [`lib/verifier.ts`](lib/verifier.ts) | `createVerifier({ profile: 'av', … })` — one verifier for the app |
| [`app/api/eudikit/[...eudikit]/route.ts`](app/api/eudikit/%5B...eudikit%5D/route.ts) | `createNextHandler(verifier, { requests: { age: … } })` — every route the browser and the wallet talk to |
| [`app/page.tsx`](app/page.tsx) | `<AgeGate/>` — the button, the QR code, the same-device link |

No signing key, no database, no service to deploy: verification runs inside this Next process.

## Run it

The wallet lives on a phone, so it has to reach this server over public HTTPS. Start a tunnel
first:

```bash
cloudflared tunnel --url http://localhost:3000
```

Take the `https://…trycloudflare.com` address it prints and start the app with it:

```bash
EUDIKIT_PUBLIC_BASE_URL=https://your-tunnel.trycloudflare.com pnpm --filter @eudikit/example-next dev
```

Open the tunnel URL (not `localhost`) and press **Verify your age with your wallet**. Scan the QR
code with the wallet on your phone, or open the same link on the device the wallet is installed on.

`ngrok http 3000` works the same way. What matters is that the URL is HTTPS and that the phone can
reach it — `direct_post` means the wallet POSTs its response straight to this server.

### Environment

| Variable | Required | Meaning |
|---|---|---|
| `EUDIKIT_PUBLIC_BASE_URL` | yes, for QR and deep link | Public HTTPS origin of this app; `response_uri` is derived from it. Missing or `localhost` fails loudly at request creation instead of producing a URI nothing can answer. |
| `EUDIKIT_ALLOW_INSECURE_LOOPBACK` | no | `1` accepts an `http://localhost` base URL, for the USB flow below. Development only; never set it in production. |
| `EUDIKIT_TRUST_MODE` | no | `strict` (default) or `permissive`. Permissive downgrades *trust* checks to warnings — signatures, digests, device authentication and nonce binding never relax — and the result reports which mode produced it. |
| `EUDIKIT_TRUST_ANCHORS` | no | PEM certificates for an issuer that is not on the AV trusted list, e.g. a local testbed. Additive: the trusted list still applies. |

## Run it over USB (no tunnel)

An Android phone plugged into the development machine can reach `localhost` directly, which skips
the tunnel entirely — useful when the network is hostile or the tunnel URL keeps changing. Forward
port 3000 from the phone to this machine:

```bash
adb reverse tcp:3000 tcp:3000
```

Then start the app pointing at loopback, with the development switch that permits it:

```bash
EUDIKIT_PUBLIC_BASE_URL=http://localhost:3000 EUDIKIT_ALLOW_INSECURE_LOOPBACK=1 pnpm --filter @eudikit/example-next dev
```

Open `http://localhost:3000` in the phone's own browser — `adb reverse` sends it to this machine —
and use the same-device link rather than the QR code. The wallet POSTs its response back over the
same forwarded port.

`EUDIKIT_ALLOW_INSECURE_LOOPBACK` buys exactly one thing: a plain-http loopback
`EUDIKIT_PUBLIC_BASE_URL` is accepted. Traffic over the cable never touches a network, so there is
nothing here for TLS to protect; a LAN address such as `http://192.168.1.10:3000` is still refused,
and no verification check changes. It is a development switch — the server prints a warning at boot
saying so.

**When it does not work:** `adb reverse` is per-connection, so re-run it after unplugging the phone
or restarting `adb`. `adb devices` must list the phone as `device`, not `unauthorized`. If the page
does not load in the phone's browser, the forward is not up — nothing about the wallet is involved
yet.

## Why there is no Digital Credentials API button

Today's AV wallet speaks only `org-iso-mdoc` over the DC API — an `openid4vp-v1-*` request shows
*no credential at all* in the picker and returns no error, so the demo would simply look broken
with nothing to debug. The SDK refuses that combination up front (`profile: 'av'` plus
`channel: 'dc-api'` throws `CHANNEL_PROFILE_MISMATCH`), and this example registers the `age`
request for `qr` and `deep-link` only.

The DC API path is real, and `@eudikit/react` negotiates it automatically — it is for Google
Wallet and the December 2026 EUDI wallets. Switch this example over by setting
`profile: 'eudi'`, allowing the `dc-api` channel in the route file, and setting
`expectedOrigins`.

## Getting a credential onto the phone

The wallet needs a Proof-of-Age attestation before it can present one. The prebuilt APK, the EU
demo issuer and the trusted-list address are all in [`../../testbed/README.md`](../../testbed/README.md),
along with the reference verifier to compare verdicts against.

## When it does not work

- **Nothing happens after scanning.** The wallet could not reach `EUDIKIT_PUBLIC_BASE_URL`. Open
  it in the phone's browser: it has to load there, not just on the laptop.
- **The link does nothing on the phone.** The deep-link scheme defaults to `eudi-openid4vp`,
  which is what today's wallet builds register. Override it per request with `scheme` if your
  build differs.
- **`verified: false` with trust failures.** In strict mode the issuer must be on the AV trusted
  list. A testbed issuer needs `EUDIKIT_TRUST_ANCHORS`, or `EUDIKIT_TRUST_MODE=permissive` while
  developing.
- **Reading the details.** Check rows are server-side by default. Pass
  `exposeDiagnostics: true` to `createNextHandler` while developing to see the full report in the
  poll response — it is written for operators, so keep it off in production.

## Production notes

The example uses `memorySessionAdapter()`, which stores sessions in one process: with more than
one instance a wallet response can land where the request never was. Swap in
`redisSessionAdapter(client)` or `kvSessionAdapter(kv)` — the rest of the code does not change.

Not affiliated with the European Commission.
