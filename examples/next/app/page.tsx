import { AgeGate } from '@eudikit/react'

/**
 * The age gate. A server component: `@eudikit/react` marks its own client boundary, so the page
 * itself needs no `'use client'`.
 *
 * `channels={['qr', 'deep-link']}` is the path today's EU AV wallet answers — the QR code for a
 * phone across the desk, and the same link for a wallet on this device. The panel below the
 * button is the widget's default UI; `fallback` replaces it when a design system has opinions.
 */
export default function Page() {
  return (
    <>
      <h1>Prove you are over 18</h1>
      <p className="lede">
        Without handing over your birth date, your name, or a document scan. Your wallet answers one
        question — <em>are you over 18?</em> — and nothing else leaves your phone.
      </p>

      <AgeGate
        endpoint="/api/eudikit"
        request="age"
        channels={['qr', 'deep-link']}
        className="gate"
      >
        <section className="unlocked">
          <h2>Verified</h2>
          <p>
            The server checked the attestation's issuer signature, its value digests, the device
            signature over this session's transcript, and the issuer's membership of the EU Age
            Verification trusted list. It learned that you are over 18 — and no more than that.
          </p>
        </section>
      </AgeGate>

      <footer>
        <p>
          Cross-device verification needs a wallet that can reach this server: set{' '}
          <code>EUDIKIT_PUBLIC_BASE_URL</code> to a public HTTPS tunnel before scanning. See this
          example's README.
        </p>
        <p>Not affiliated with the European Commission.</p>
      </footer>
    </>
  )
}
