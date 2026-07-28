/**
 * `certificateBytesEqual` gets its own suite because three independent trust decisions rest on
 * it: trusted-list membership (DS-direct-match), trust anchor matching, and the device MAC tag
 * comparison. A comparison that answers "equal" for anything short of identical bytes turns all
 * three into decoration, and the flows above cannot see the difference — their fixtures happen
 * to differ in length and in their first bytes.
 */

import { describe, expect, it } from 'vitest'
import { certificateBytesEqual, toDerCertificates } from '../src/verify/certificates.js'

/** Long enough that a difference in the tail sits beyond any plausible prefix window. */
const REFERENCE = Uint8Array.from([
  0x30, 0x82, 0x01, 0x0a, 0x02, 0x01, 0x01, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
  0x04, 0x03, 0x02, 0x30, 0x1f, 0x31, 0x0b, 0x30,
])

describe('certificateBytesEqual', () => {
  it('accepts byte-identical inputs', () => {
    expect(certificateBytesEqual(REFERENCE, Uint8Array.from(REFERENCE))).toBe(true)
    expect(certificateBytesEqual(new Uint8Array(0), new Uint8Array(0))).toBe(true)
  })

  it('rejects same-length inputs wherever the difference sits', () => {
    for (const index of [0, 11, REFERENCE.length - 1]) {
      const altered = Uint8Array.from(REFERENCE)
      altered[index] = (altered[index] as number) ^ 0x01
      expect(certificateBytesEqual(REFERENCE, altered), `differs at byte ${index}`).toBe(false)
      expect(certificateBytesEqual(altered, REFERENCE), `differs at byte ${index}`).toBe(false)
    }
  })

  it('rejects inputs of different length, a shared prefix included', () => {
    const prefix = REFERENCE.subarray(0, 20)
    expect(certificateBytesEqual(REFERENCE, prefix)).toBe(false)
    expect(certificateBytesEqual(prefix, REFERENCE)).toBe(false)
  })
})

describe('toDerCertificates', () => {
  it('splits a multi-block PEM bundle and keeps the DER bytes intact', () => {
    const der = Uint8Array.from([0x30, 0x03, 0x02, 0x01, 0x01])
    const block = `-----BEGIN CERTIFICATE-----\n${Buffer.from(der).toString('base64')}\n-----END CERTIFICATE-----\n`
    const parsed = toDerCertificates(block + block, 'test')

    expect(parsed).toHaveLength(2)
    for (const certificate of parsed) {
      expect(certificateBytesEqual(certificate, der)).toBe(true)
    }
  })
})
