/**
 * Certificate input normalization: the public API accepts PEM strings or raw DER bytes
 * (`CertificateInput`), the verification layer works on DER only.
 */

import type { CertificateInput } from '../types.js'
import { EudikitError } from '../types.js'

const PEM_CERTIFICATE =
  /-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\r\n\s]+?)-----END CERTIFICATE-----/g

/**
 * Normalizes one `CertificateInput` into DER certificates. A PEM string may carry several
 * `BEGIN CERTIFICATE` blocks (a bundle file pasted as one string); each becomes its own entry.
 */
export function toDerCertificates(input: CertificateInput, source: string): Uint8Array[] {
  if (input instanceof Uint8Array) {
    if (input.length === 0) {
      throw new EudikitError('CONFIG_INVALID', `${source} is an empty byte array`)
    }
    return [input]
  }

  if (typeof input !== 'string' || input.trim() === '') {
    throw new EudikitError(
      'CONFIG_INVALID',
      `${source} must be a PEM certificate string or DER bytes`
    )
  }

  const certificates: Uint8Array[] = []
  for (const match of input.matchAll(PEM_CERTIFICATE)) {
    const base64 = (match[1] ?? '').replace(/\s+/g, '')
    if (base64 === '') continue
    let bytes: Uint8Array
    try {
      bytes = Uint8Array.from(Buffer.from(base64, 'base64'))
    } catch (cause) {
      throw new EudikitError('CONFIG_INVALID', `${source} contains a malformed PEM body`, {
        cause,
      })
    }
    if (bytes.length === 0) {
      throw new EudikitError('CONFIG_INVALID', `${source} contains an empty PEM body`)
    }
    certificates.push(bytes)
  }

  if (certificates.length === 0) {
    throw new EudikitError(
      'CONFIG_INVALID',
      `${source} contains no "-----BEGIN CERTIFICATE-----" block — pass PEM text or DER bytes`
    )
  }
  return certificates
}

export function certificateBytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number)
  return diff === 0
}
