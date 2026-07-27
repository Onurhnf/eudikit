import { cleanup, render } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'
import { en } from '../src/locales/index.js'
import { QrCode, VerificationQr } from '../src/qr-code.js'

afterEach(cleanup)

describe('<QrCode/>', () => {
  it('renders a self-contained SVG with the mandated quiet zone', () => {
    const { container } = render(<QrCode value="eudi-openid4vp://authorize?client_id=x" />)
    const svg = container.querySelector('svg')
    if (svg === null) throw new Error('no svg rendered')

    const viewBox = svg.getAttribute('viewBox')?.split(' ') ?? []
    const modules = Number(viewBox[2])
    // Version 1 is 21 modules; anything scannable carries four modules of quiet zone per side.
    expect(modules).toBeGreaterThanOrEqual(21 + 8)
    expect(modules % 4).toBe(1)
    expect(svg.getAttribute('width')).toBe('240')
    expect(svg.getAttribute('role')).toBe('img')
    expect(svg.querySelector('path')?.getAttribute('d')).toContain('M')
    // No script, no external reference: the markup renders under a strict CSP.
    expect(container.innerHTML).not.toContain('http://www.w3.org/1999/xlink')
  })

  it('grows with the payload and honours size and label', () => {
    const short = render(<QrCode value="a" />).container.querySelector('svg')
    cleanup()
    const long = render(
      <QrCode value={`https://rp.example/?q=${'x'.repeat(600)}`} size={320} label="Scan me" />
    ).container.querySelector('svg')

    const edge = (element: Element | null): number =>
      Number(element?.getAttribute('viewBox')?.split(' ')[2] ?? 0)
    expect(edge(long)).toBeGreaterThan(edge(short))
    expect(long?.getAttribute('width')).toBe('320')
    expect(long?.getAttribute('aria-label')).toBe('Scan me')
  })
})

describe('<VerificationQr/>', () => {
  it('renders the payload with the catalog default label and forwards data attributes', () => {
    const { container } = render(
      <VerificationQr
        payload="eudi-openid4vp://authorize?client_id=x"
        data-part="qr"
        data-state="polling"
      />
    )
    const svg = container.querySelector('svg')
    expect(svg?.getAttribute('role')).toBe('img')
    expect(svg?.getAttribute('aria-label')).toBe(en.qrLabel)
    expect(svg?.getAttribute('data-part')).toBe('qr')
    expect(svg?.getAttribute('data-state')).toBe('polling')
    expect(svg?.querySelector('path')?.getAttribute('d')).toContain('M')
  })

  it('honours size, className and label like the underlying <QrCode/>', () => {
    const { container } = render(
      <VerificationQr payload="a" size={320} className="qr" label="Scan me" />
    )
    const svg = container.querySelector('svg')
    expect(svg?.getAttribute('width')).toBe('320')
    expect(svg?.getAttribute('class')).toBe('qr')
    expect(svg?.getAttribute('aria-label')).toBe('Scan me')
  })
})
