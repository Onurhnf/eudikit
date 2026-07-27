# testbed — local AV wallet test rig

Command-level notes for standing up the EU Age Verification reference stack next to eudikit.
Everything marked `VERIFIED` below was actually run on a Mac; everything else is labelled.

**The shape of the rig:** let the EU host the issuer, run the verifier locally.

```
[Android phone / emulator]                        [Mac]
 AV Wallet APK (prebuilt, ~188 MB) ──issuance──>  EU live demo issuer (internet)
        │
        └──presentation──> local verifier stack (docker compose)
                                   └──> @eudikit/core (our code, compared against it)
```

Issuance is not worth reproducing locally: the issuer is a three-service chain whose GHCR image is
not published (403) and which has two upstream boot-time bugs. The EU's live demo issuer works,
and issuance is not our product anyway — we are the verifier side.

## 1. EU reference verifier — one command `VERIFIED`

```bash
git clone --depth 1 https://github.com/eu-digital-identity-wallet/av-srv-verifier-endpoint.git
cd av-srv-verifier-endpoint/docker && docker compose up -d
```

Self-sufficient: `keystore.jks`, `haproxy.conf` and `haproxy.pem` are all in the repository. Boot
takes ~18 s (Spring Boot). Result: `verifier-backend` on 8080, `verifier-ui` on 4300, `haproxy` on
443.

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/public/openapi.json   # 200
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:4300/                       # 200
```

Two environment variables matter more than the rest:

| Variable | Value | Why |
|---|---|---|
| `VERIFIER_MDOC_REDIRECTURICLIENTIDINDEVICEAUTHHANDOVER` | `true` | **Required by the AV wallet.** Without it the handover carries the wrong client id and device auth fails. |
| `VERIFIER_ALWAYSACCEPTWALLETRESPONSE` | `true` | Debug mode: returns 200 even when verification failed, with a `trust_info` report attached. Useful for reading, disastrous as a default — this is exactly the posture eudikit inverts. |

> ⚠️ `VERIFIER_PUBLICURL` defaults to `http://localhost:8080`, which a phone cannot reach. Either
> `adb reverse tcp:8080 tcp:8080`, or point it at your LAN IP. On Apple Silicon every image is
> amd64 and runs under Rosetta — slower, but it works.

[`docker-compose.yml`](docker-compose.yml) here is a **skeleton** for bringing the backend up on
its own for comparison testing, without cloning the upstream repo. The verified path is the clone
above; read the header of that file before using it.

## 2. AV wallet on the device `VERIFIED` (link live; `adb` steps not run)

No build needed — there is a prebuilt APK. Release `2026.07-1` (10 July 2026), 197,285,000 bytes.

```bash
curl -L -o av-wallet.apk https://github.com/eu-digital-identity-wallet/av-app-android-wallet-ui/releases/download/2026.07-1/app-demo-release.apk
adb install -r av-wallet.apk
adb reverse tcp:8080 tcp:8080
```

**iOS has no prebuilt binary** — all 14 releases have empty asset lists and there is no TestFlight
link. Building it yourself in Xcode is the only route.

## 3. AV Trusted List — the exact address `VERIFIED`

```
https://acceptance.trust.tech.ec.europa.eu/lists/age-verification/av-tl.xml
```

Live, 69,104 bytes, ETSI TS 119 612 XML. Sequence number 17, issued 2026-06-24, scheme operator
"European Commission". It carries **12 Proof-of-Age Attestation providers** (11 recognized, 1
deprecated) under 7 TSPs, including the EU's own reference issuer `Age Verification DS - 001` —
so a credential obtained from the demo issuer really can be checked against the real list.

The production address has **not** been announced anywhere: `https://ec.europa.eu/tools/lotl/av/av-tl.xml`
returns 404 and that string does not appear in the XML at all; the list's own `TSLLocation` points
at the acceptance URL above.

## 4. Trust validator — source build only `VERIFIED`

The published image boots with two extra environment variables, but the **age-verification use
case is not in it**: `POST /trust` answers
`No configuration found for VerificationContext EAA(useCase=age-verification)`. The repository's
`main` has the AV entry active, so building from source is the working route:

```bash
cd av-srv-trust-validator && ./gradlew bootRun --args='--server.port=8082'
```

Verified against a real `Age Verification DS - 001` certificate pulled from the live list:
`{"trusted": true, "trustAnchor": "…"}` in 44 ms.

## 5. Device day checklist

The order to work through with a phone on the desk. Nothing in this section has been run end to
end yet — that is what the day is for — so every step carries the thing to look at when it stalls.

1. **Install the wallet.** The APK and the two `adb` commands are in §2. `adb devices` has to list
   the phone as `device`; `unauthorized` means the USB-debugging prompt on the phone was never
   accepted.
2. **Get a Proof-of-Age attestation onto it.** Use the wallet's own add-document flow against the
   EU demo issuer — issuance is not reproduced locally (§1). *No credential afterwards:* the phone
   needs plain internet for this step, not the USB forward, and the wallet reports issuer errors in
   its own UI rather than at presentation time.
3. **Forward the port.** `adb reverse tcp:3000 tcp:3000`. *It is per-connection:* unplugging the
   phone or restarting `adb` drops it silently, and the next request just times out.
4. **Start the example app in USB mode.**
   ```bash
   EUDIKIT_PUBLIC_BASE_URL=http://localhost:3000 EUDIKIT_ALLOW_INSECURE_LOOPBACK=1 pnpm --filter @eudikit/example-next dev
   ```
   *Request creation throws `CONFIG_PUBLIC_BASE_URL_*`:* one of the two variables did not reach the
   process. The boot log prints the insecure-loopback warning when the switch is on.
5. **Open `http://localhost:3000` in the phone's browser.** *Page does not load:* step 3 is not up —
   the wallet is not involved yet. A tunnel URL (`examples/next/README.md`) is the alternative when
   the forward cannot be made to work.
6. **Press the same-device link, not the QR code.** The QR is for scanning from a second device.
   *Nothing opens:* the deep-link scheme this build registers is not `eudi-openid4vp` — check the
   installed APK's intent filters and override it per request with `scheme`.
7. **Approve in the wallet, then watch the page.** The result appears through polling.
   *Approved but the page never resolves:* the wallet could not POST back — the response goes to
   `http://localhost:3000/api/eudikit/wallet/response` over the same forward, so check the server
   log for the request arriving at all.
8. **Read the verdict.** A `verified: false` in strict mode is a real answer, not a failure of the
   rig: the demo issuer is on the live AV list (§3), so a trust failure here is worth diffing
   against the reference verifier (§1) check by check.

## 6. What this rig is for

Two things, in this order:

1. **Comparison testing.** Feed the same `DeviceResponse` to the EU verifier and to
   `@eudikit/core`, and diff the verdicts check by check. Their twelve `MsoMdocCheck`s map onto our
   `CheckId` taxonomy one-to-one, so a disagreement is always locatable.
2. **Closing the open questions** that cannot be closed at a desk:
   whether the deep-link scheme is really `eudi-openid4vp` rather than
   `av://`, what the `apk-key-hash` origin looks like in a real response, how a wrong protocol
   fails on a real device, and whether the wallet's own `SessionTranscript` bytes match ours.

On that last one, half the answer is already in: `@owf/mdoc` 0.7.0 and our encoder produce
byte-identical `SessionTranscript`s, and both match the OpenID4VP 1.0 B.2.6 vectors
(`packages/core/test/session-transcript.test.ts`). What remains is whether the *wallet* agrees —
which needs a real device, which needs this rig.
