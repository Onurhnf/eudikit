// @vitest-environment node

/**
 * The package has to survive a server render: a Next.js app imports it from a module graph
 * that has no `window`, no `document` and no `navigator`. Importing must not touch any of
 * them, and `<AgeGate/>` must render its closed state to HTML.
 */

import { describe, expect, it } from 'vitest'

describe('server rendering', () => {
  it('imports and renders without a DOM', async () => {
    expect(typeof globalThis.window).toBe('undefined')
    expect(typeof globalThis.document).toBe('undefined')

    const {
      AgeGate,
      digitalCredentialsAvailable,
      getLabels,
      QrCode,
      useVerification,
      VerificationQr,
    } = await import('../src/index.js')
    expect(typeof useVerification).toBe('function')
    expect(digitalCredentialsAvailable()).toBe(false)

    // The catalogs are plain data and safe in a server module graph.
    const { tr } = await import('../src/locales/index.js')
    expect(getLabels('tr').trigger).toBe(tr.trigger)

    const { renderToStaticMarkup } = await import('react-dom/server')
    const html = renderToStaticMarkup(
      <AgeGate endpoint="/api/eudikit">
        <p>Adults only</p>
      </AgeGate>
    )

    expect(html).toContain('Verify your age with your wallet')
    expect(html).toContain('data-eudikit-status="idle"')
    expect(html).toContain('data-state="idle"')
    expect(html).toContain('lang="en"')
    // The gate is closed on the server: protected content is never sent to an unverified client.
    expect(html).not.toContain('Adults only')

    // The QR renderers are pure markup, so they server-render too.
    expect(renderToStaticMarkup(<QrCode value="eudi-openid4vp://authorize" />)).toContain('<svg')
    expect(renderToStaticMarkup(<VerificationQr payload="eudi-openid4vp://authorize" />)).toContain(
      '<svg'
    )
  })
})
