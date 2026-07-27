import { cleanup, render } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'
import { QrCode } from '../src/qr-code.js'

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
