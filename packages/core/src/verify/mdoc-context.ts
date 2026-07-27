/**
 * The production `MdocContext` handed to `@owf/mdoc` — every cryptographic and X.509 primitive
 * the mdoc verification chain calls out to.
 *
 * Two deliberate implementation choices:
 *
 *  - **COSE signature verification dispatches on the COSE `alg` header** (ES256/ES384/ES512 →
 *    P-256/P-384/P-521), falling back to the key's own curve when no algorithm reaches the
 *    callback (the device-auth path passes only the MSO device key). Assuming P-256 would
 *    silently break P-384/P-521 issuers.
 *  - **X.509 work runs on `node:crypto`'s `X509Certificate`**, not a userland parser: the DS
 *    certificates the EU issuing infrastructure produces carry an `issuerAltName` encoding that
 *    strict userland parsers (e.g. `@peculiar/x509`) refuse to parse, while Node's OpenSSL-backed
 *    parser accepts them.
 *
 * Chain validation is DS-direct-match in this release: the head of the presented chain must be
 * byte-equal to a configured trust anchor. PKIX path building from a CA anchor arrives together
 * with the trusted-list layer.
 */

import { createHash, createHmac, hkdfSync, randomBytes, X509Certificate } from 'node:crypto'
import { p256, p384, p521 } from '@noble/curves/nist.js'
import { CoseKey, type MdocContext } from '@owf/mdoc'
import { EudikitError } from '../types.js'
import { certificateBytesEqual } from './certificates.js'

/** COSE algorithm identifiers (RFC 9053) for the ECDSA family this release accepts. */
const COSE_ALG_ES256 = -7
const COSE_ALG_ES384 = -35
const COSE_ALG_ES512 = -36

/** COSE elliptic-curve identifiers (RFC 9053 §7.1). */
const COSE_CRV_P256 = 1
const COSE_CRV_P384 = 2
const COSE_CRV_P521 = 3

type NistCurve = typeof p256

interface EcdsaSuite {
  curve: NistCurve
  /** Uncompressed SEC1 point length — doubles as the curve fallback discriminator. */
  pointLength: number
}

const SUITES: Record<number, EcdsaSuite> = {
  [COSE_ALG_ES256]: { curve: p256, pointLength: 65 },
  [COSE_ALG_ES384]: { curve: p384, pointLength: 97 },
  [COSE_ALG_ES512]: { curve: p521, pointLength: 133 },
}

function suiteForAlgorithm(algorithm: number): EcdsaSuite {
  const suite = SUITES[algorithm]
  if (suite === undefined) {
    throw new EudikitError(
      'PRESENTATION_MALFORMED',
      `unsupported COSE signature algorithm ${algorithm} — this release accepts ES256 (-7), ` +
        'ES384 (-35) and ES512 (-36)'
    )
  }
  return suite
}

function suiteForKey(key: CoseKey): EcdsaSuite {
  if (typeof key.algorithm === 'number' && key.algorithm in SUITES) {
    return suiteForAlgorithm(key.algorithm)
  }
  switch (key.curve) {
    case COSE_CRV_P256:
      return SUITES[COSE_ALG_ES256] as EcdsaSuite
    case COSE_CRV_P384:
      return SUITES[COSE_ALG_ES384] as EcdsaSuite
    case COSE_CRV_P521:
      return SUITES[COSE_ALG_ES512] as EcdsaSuite
    default:
      throw new EudikitError(
        'PRESENTATION_MALFORMED',
        'cannot determine the ECDSA curve of a COSE key that carries neither a supported ' +
          'algorithm nor a supported curve'
      )
  }
}

function nodeDigestName(digestAlgorithm: string): string {
  switch (digestAlgorithm) {
    case 'SHA-256':
      return 'sha256'
    case 'SHA-384':
      return 'sha384'
    case 'SHA-512':
      return 'sha512'
    default:
      throw new EudikitError(
        'PRESENTATION_MALFORMED',
        `unsupported digest algorithm "${digestAlgorithm}"`
      )
  }
}

/**
 * ECDH shared secret via `@noble/curves`: the x-coordinate of `d · Q`, which is the `Z` input
 * ISO 18013-5 §9.1.1.5 feeds into HKDF for the session/EMac keys.
 */
function ecdhSharedSecretX(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  const suite =
    publicKey.length === 97
      ? (SUITES[COSE_ALG_ES384] as EcdsaSuite)
      : publicKey.length === 133
        ? (SUITES[COSE_ALG_ES512] as EcdsaSuite)
        : (SUITES[COSE_ALG_ES256] as EcdsaSuite)
  const shared = suite.curve.getSharedSecret(privateKey, publicKey)
  // getSharedSecret returns a compressed SEC1 point (prefix byte + x); drop the prefix.
  return shared.subarray(1)
}

function parseCertificate(certificate: Uint8Array): X509Certificate {
  try {
    return new X509Certificate(certificate)
  } catch (cause) {
    throw new EudikitError('PRESENTATION_MALFORMED', 'X.509 certificate does not parse', {
      cause,
    })
  }
}

/**
 * Reads one field of an X.509 distinguished name as Node renders it (one `KEY=value` line per
 * attribute, multi-valued RDNs joined with `+`).
 */
function dnFields(distinguishedName: string, field: string): string[] {
  const values: string[] = []
  for (const line of distinguishedName.split('\n')) {
    for (const part of line.split('+')) {
      const trimmed = part.trim()
      if (trimmed.startsWith(`${field}=`)) values.push(trimmed.slice(field.length + 1))
    }
  }
  return values
}

export interface TrustAnchors {
  /** DER trust anchors the chain head must byte-match. */
  anchors: Uint8Array[]
}

/** The `Pick` of `MdocContext` that `Verifier.verifyDeviceResponse` consumes. */
export type VerifyMdocContext = Pick<MdocContext, 'cose' | 'x509' | 'crypto' | 'fetch'>

export function createMdocContext(): VerifyMdocContext {
  return {
    fetch: globalThis.fetch,

    crypto: {
      random: (length) => randomBytes(length),

      digest: ({ digestAlgorithm, bytes }) =>
        new Uint8Array(createHash(nodeDigestName(digestAlgorithm)).update(bytes).digest()),

      hdkf: ({ digestAlgorithm, privateKey, publicKey, salt, info }) => {
        const ikm = ecdhSharedSecretX(privateKey, publicKey)
        const derived = hkdfSync(nodeDigestName(digestAlgorithm ?? 'SHA-256'), ikm, salt, info, 32)
        return new Uint8Array(derived)
      },
    },

    cose: {
      sign1: {
        sign: async ({ toBeSigned, key, algorithm }) => {
          const suite = suiteForAlgorithm(algorithm)
          return suite.curve.sign(toBeSigned, key.privateKey, { prehash: true })
        },
        verify: async ({ toBeVerified, signature, key, algorithm }) => {
          const suite = algorithm === undefined ? suiteForKey(key) : suiteForAlgorithm(algorithm)
          // `lowS: false` matters: X.509/COSE ecosystems do not normalize ECDSA `s`, and noble's
          // default (`lowS: true`, the BTC/ETH convention) would reject ~half of all valid
          // wallet signatures.
          return suite.curve.verify(signature, toBeVerified, key.publicKey, {
            prehash: true,
            lowS: false,
            format: 'compact',
          })
        },
      },
      mac0: {
        authenticate: async ({ toBeAuthenticated, key }) => {
          const raw = key instanceof CoseKey ? key.privateKey : key
          return rawHmac(raw, toBeAuthenticated)
        },
        verify: async ({ toBeAuthenticated, key, tag }) => {
          const raw = key instanceof CoseKey ? key.privateKey : key
          return certificateBytesEqual(rawHmac(raw, toBeAuthenticated), tag)
        },
      },
    },

    x509: {
      getCertificateData: ({ certificate }) => {
        const cert = parseCertificate(certificate)
        return {
          issuerName: cert.issuer,
          subjectName: cert.subject,
          serialNumber: cert.serialNumber,
          thumbprint: cert.fingerprint256,
          notBefore: new Date(cert.validFrom),
          notAfter: new Date(cert.validTo),
          pem: cert.toString(),
        }
      },

      getIssuerNameField: ({ certificate, field }) =>
        dnFields(parseCertificate(certificate).subject, field),

      getPublicKey: async ({ certificate }) => {
        const cert = parseCertificate(certificate)
        const jwk = cert.publicKey.export({ format: 'jwk' })
        return CoseKey.fromJwk(jwk as Record<string, unknown>)
      },

      verifyCertificateChain: ({ trustedCertificates, x5chain, now }) => {
        const head = x5chain[0]
        if (head === undefined) {
          throw new EudikitError(
            'PRESENTATION_MALFORMED',
            'the presentation carries an empty x5chain'
          )
        }
        const matched = trustedCertificates.some((anchor) => certificateBytesEqual(anchor, head))
        if (!matched) {
          throw new EudikitError(
            'VERIFICATION_FAILED',
            'the document signer certificate does not byte-match any configured trust anchor ' +
              '(DS-direct-match); PKIX path building from CA anchors is not implemented in ' +
              'this release'
          )
        }
        const cert = parseCertificate(head)
        const at = now ?? new Date()
        if (at < new Date(cert.validFrom) || at > new Date(cert.validTo)) {
          throw new EudikitError(
            'VERIFICATION_FAILED',
            'the document signer certificate is outside its validity period'
          )
        }
        return { chain: [head] }
      },
    },
  }
}

function rawHmac(key: Uint8Array, data: Uint8Array): Uint8Array {
  return new Uint8Array(createHmac('sha256', key).update(data).digest())
}
