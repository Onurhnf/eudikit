/**
 * A QR code as plain SVG elements.
 *
 * The payload is encoded with `uqr` — a dependency-free encoder that returns the module matrix
 * and nothing else — and this component turns that matrix into one `<path>`. No canvas, no
 * `dangerouslySetInnerHTML`, no `new Function`: the output is ordinary React elements, so it
 * renders under a strict Content-Security-Policy and on the server alike.
 *
 * Two fixed choices, both about actually being scannable rather than about looks: the quiet
 * zone is the four modules the QR specification asks for, and the colours are hard dark-on-light
 * (a QR code inverted to match a dark theme does not scan on many readers).
 */

import { type ReactElement, useMemo } from 'react'
import { encode } from 'uqr'

/** Modules of quiet zone around the symbol (ISO/IEC 18004 §6.3.8). */
const QUIET_ZONE = 4

export interface QrCodeProps {
  /** The string to encode — for eudikit, the `qrPayload` of a created request. */
  value: string
  /** Rendered edge length in CSS pixels. Default 240. */
  size?: number
  className?: string
  /** Accessible name of the image. */
  label?: string
}

export function QrCode({
  value,
  size = 240,
  className,
  label = 'Wallet request QR code',
}: QrCodeProps): ReactElement {
  const { modules, path } = useMemo(() => {
    // Error correction stays at the lowest level on purpose: an unsigned by-value request
    // carries its whole DCQL query in the URI, and capacity is the scarce resource here.
    const encoded = encode(value, { border: QUIET_ZONE, ecc: 'L' })
    return { modules: encoded.size, path: toPath(encoded.data) }
  }, [value])

  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox={`0 0 ${modules} ${modules}`}
      width={size}
      height={size}
      shapeRendering="crispEdges"
      role="img"
      aria-label={label}
      className={className}
    >
      <rect width={modules} height={modules} fill="#ffffff" />
      <path d={path} fill="#000000" />
    </svg>
  )
}

/** One `<path>` for the whole symbol: a unit square per dark module. */
function toPath(matrix: boolean[][]): string {
  const parts: string[] = []
  for (let y = 0; y < matrix.length; y += 1) {
    const row = matrix[y] as boolean[]
    for (let x = 0; x < row.length; x += 1) {
      if (row[x] === true) parts.push(`M${x} ${y}h1v1h-1z`)
    }
  }
  return parts.join('')
}
