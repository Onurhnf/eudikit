# @eudikit/react

Browser transport for eudikit: `useVerification()` (headless) and `<AgeGate/>` (the widget on top
of it).

> **Pre-release skeleton — not published.** The public surface is stable; both exports throw
> today.

This package **never verifies anything**. It calls `navigator.credentials.get()`, falls back to a
QR code when the Digital Credentials API is unavailable, polls the server for the result, and
renders. All cryptography lives in `@eudikit/core` on the server — client-side verification would
be no verification at all.

What the package will own so that integrators do not have to:

- the `typeof DigitalCredential` guard and `userAgentAllowsProtocol()` negotiation;
- automatic fall back to the QR channel (progressive enhancement);
- calling `start()` from a user gesture — the DC API consumes transient activation;
- mapping `NotAllowedError` onto the honest, deliberately combined
  `USER_DECLINED_OR_NO_CREDENTIAL`;
- polling that backs off and pauses while the tab is hidden.

`diagnostics` never reaches the client by default; exposing it is a server-side opt-in
(`exposeDiagnostics` on the core handler).

Apache-2.0. Not affiliated with the European Commission.
