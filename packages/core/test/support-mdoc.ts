/**
 * Test fixtures for the response side: a synthetic PKI (self-signed DS certificate + device
 * key) and a wallet simulator that issues a real AV attestation and signs a real
 * `DeviceResponse` over a given SessionTranscript — the same `@owf/mdoc` issuance APIs the
 * upstream project drives its own verifier tests with, so what the chain verifies here is a
 * genuine mdoc, not a hand-mocked structure.
 *
 * The X.509 part is a ~80-line DER writer producing a v1 self-signed certificate. That is all
 * DS-direct-match needs (the verifier byte-compares the DS certificate against the anchors and
 * reads subject/validity via `node:crypto`), and it keeps the test tree free of certificate
 * library dependencies.
 */

import { createSign, generateKeyPairSync, type KeyObject } from 'node:crypto'
import {
  DeviceKey,
  DeviceResponse,
  type DeviceResponse as DeviceResponseType,
  DeviceSignedBuilder,
  Document,
  type IssuerSigned,
  IssuerSignedBuilder,
  SessionTranscript,
  SignatureAlgorithm,
} from '@owf/mdoc'
import { createMdocContext } from '../src/verify/mdoc-context.js'

export const AV_DOCTYPE = 'eu.europa.ec.av.1'

export const FIXED_NOW = new Date('2026-07-27T12:00:00.000Z')

const ctx = createMdocContext()

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

export interface TestKeyPair {
  privateKey: KeyObject
  publicKey: KeyObject
  privateJwk: Record<string, unknown>
  publicJwk: Record<string, unknown>
}

export function p256KeyPair(): TestKeyPair {
  return ecKeyPair('P-256')
}

export function ecKeyPair(namedCurve: 'P-256' | 'P-384' | 'P-521'): TestKeyPair {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve })
  return {
    privateKey,
    publicKey,
    privateJwk: privateKey.export({ format: 'jwk' }) as Record<string, unknown>,
    publicJwk: publicKey.export({ format: 'jwk' }) as Record<string, unknown>,
  }
}

// ---------------------------------------------------------------------------
// Minimal DER writer — X.509 v1 self-signed certificate
// ---------------------------------------------------------------------------

function der(tag: number, content: Uint8Array): Uint8Array {
  let lengthBytes: number[]
  if (content.length < 0x80) lengthBytes = [content.length]
  else if (content.length <= 0xff) lengthBytes = [0x81, content.length]
  else lengthBytes = [0x82, content.length >>> 8, content.length & 0xff]
  const out = new Uint8Array(1 + lengthBytes.length + content.length)
  out[0] = tag
  out.set(lengthBytes, 1)
  out.set(content, 1 + lengthBytes.length)
  return out
}

function concat(...chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0)
  const out = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    out.set(chunk, offset)
    offset += chunk.length
  }
  return out
}

const derSeq = (...items: Uint8Array[]) => der(0x30, concat(...items))
const derSet = (...items: Uint8Array[]) => der(0x31, concat(...items))
const derPrintable = (value: string) => der(0x13, new TextEncoder().encode(value))
const derUtf8 = (value: string) => der(0x0c, new TextEncoder().encode(value))

function derInteger(value: number): Uint8Array {
  const bytes: number[] = []
  let rest = value
  do {
    bytes.unshift(rest & 0xff)
    rest = Math.floor(rest / 256)
  } while (rest > 0)
  if ((bytes[0] as number) & 0x80) bytes.unshift(0)
  return der(0x02, Uint8Array.from(bytes))
}

function derOid(bytes: number[]): Uint8Array {
  return der(0x06, Uint8Array.from(bytes))
}

function derUtcTime(date: Date): Uint8Array {
  const pad = (n: number) => String(n).padStart(2, '0')
  const value =
    pad(date.getUTCFullYear() % 100) +
    pad(date.getUTCMonth() + 1) +
    pad(date.getUTCDate()) +
    pad(date.getUTCHours()) +
    pad(date.getUTCMinutes()) +
    pad(date.getUTCSeconds()) +
    'Z'
  return der(0x17, new TextEncoder().encode(value))
}

const OID_ECDSA_WITH_SHA256 = derOid([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02])
const OID_COUNTRY = derOid([0x55, 0x04, 0x06])
const OID_COMMON_NAME = derOid([0x55, 0x04, 0x03])

function name(commonName: string, country: string): Uint8Array {
  return derSeq(
    derSet(derSeq(OID_COUNTRY, derPrintable(country))),
    derSet(derSeq(OID_COMMON_NAME, derUtf8(commonName)))
  )
}

export interface CertificateOptions {
  commonName: string
  country?: string
  serial?: number
  notBefore?: Date
  notAfter?: Date
  /** dNSName subjectAltName entries; their presence upgrades the certificate to v3. */
  san?: string[]
}

const OID_SUBJECT_ALT_NAME = derOid([0x55, 0x1d, 0x11])

/**
 * DER-encoded self-signed X.509 certificate over the pair's public key — v1, or v3 with a
 * subjectAltName extension when `san` is given (the shape the `x509_san_dns` prefix needs).
 */
export function selfSignedCertificate(keys: TestKeyPair, options: CertificateOptions): Uint8Array {
  const subject = name(options.commonName, options.country ?? 'UT')
  const spki = new Uint8Array(keys.publicKey.export({ type: 'spki', format: 'der' }))
  const core = [
    derInteger(options.serial ?? 1),
    derSeq(OID_ECDSA_WITH_SHA256),
    subject,
    derSeq(
      derUtcTime(options.notBefore ?? new Date(FIXED_NOW.getTime() - 86_400_000)),
      derUtcTime(options.notAfter ?? new Date(FIXED_NOW.getTime() + 180 * 86_400_000))
    ),
    subject,
    spki,
  ]
  const tbs =
    options.san === undefined || options.san.length === 0
      ? derSeq(...core)
      : derSeq(
          // version [0] EXPLICIT v3(2)
          der(0xa0, derInteger(2)),
          ...core,
          // extensions [3] EXPLICIT: one subjectAltName with dNSName ([2] IA5String) entries
          der(
            0xa3,
            derSeq(
              derSeq(
                OID_SUBJECT_ALT_NAME,
                der(
                  0x04,
                  derSeq(...options.san.map((dns) => der(0x82, new TextEncoder().encode(dns))))
                )
              )
            )
          )
        )
  const signature = new Uint8Array(createSign('SHA256').update(tbs).sign(keys.privateKey))
  return derSeq(tbs, derSeq(OID_ECDSA_WITH_SHA256), der(0x03, concat(Uint8Array.of(0), signature)))
}

// ---------------------------------------------------------------------------
// Issuance + wallet simulation
// ---------------------------------------------------------------------------

export interface IssuerFixture {
  keys: TestKeyPair
  certificate: Uint8Array
}

export function makeIssuer(commonName = 'Test AV DS'): IssuerFixture {
  const keys = p256KeyPair()
  return { keys, certificate: selfSignedCertificate(keys, { commonName }) }
}

export interface IssueOptions {
  issuer: IssuerFixture
  devicePublicJwk: Record<string, unknown>
  docType?: string
  namespace?: string
  claims?: Record<string, unknown>
  validity?: { signed?: Date; validFrom?: Date; validUntil?: Date }
}

/** Issues a real `IssuerSigned` (MSO + namespaces) with the fixture DS key. */
export async function issueAttestation(options: IssueOptions): Promise<IssuerSigned> {
  const docType = options.docType ?? AV_DOCTYPE
  const namespace = options.namespace ?? docType
  const claims = options.claims ?? { age_over_18: true }
  const signed = options.validity?.signed ?? new Date(FIXED_NOW.getTime() - 3_600_000)
  return new IssuerSignedBuilder(docType, ctx).addIssuerNamespace(namespace, claims).sign({
    signingKey: coseKeyFromJwk(options.issuer.keys.privateJwk),
    algorithm: SignatureAlgorithm.ES256,
    digestAlgorithm: 'SHA-256',
    validityInfo: {
      signed,
      validFrom: options.validity?.validFrom ?? signed,
      validUntil: options.validity?.validUntil ?? new Date(FIXED_NOW.getTime() + 90 * 86_400_000),
    },
    deviceKeyInfo: { deviceKey: coseKeyFromJwk(options.devicePublicJwk) },
    certificates: [options.issuer.certificate],
  })
}

function coseKeyFromJwk(jwk: Record<string, unknown>): DeviceKey {
  // Node's JWK export carries no `alg`; the COSE signing APIs resolve their algorithm from the
  // key, so it is pinned here.
  return DeviceKey.fromJwk({ ...jwk, alg: 'ES256' }) as DeviceKey
}

export interface WalletSignOptions {
  issuerSigned: IssuerSigned
  devicePrivateJwk: Record<string, unknown>
  sessionTranscript: Uint8Array
  docType?: string
}

/**
 * The wallet side of the exchange: signs `DeviceAuthentication` over the given transcript with
 * the device key and returns the base64url `DeviceResponse` a wallet would POST as its
 * `vp_token` entry.
 */
export async function walletSignResponse(options: WalletSignOptions): Promise<string> {
  const docType = options.docType ?? AV_DOCTYPE
  const deviceSigned = await new DeviceSignedBuilder(docType, ctx).sign({
    signingKey: coseKeyFromJwk(options.devicePrivateJwk),
    algorithm: SignatureAlgorithm.ES256,
    sessionTranscript: SessionTranscript.decode(options.sessionTranscript),
    certificate: options.issuerSigned.issuerAuth.certificate,
  })
  const document = Document.create({
    docType,
    issuerSigned: options.issuerSigned,
    deviceSigned,
  })
  const response: DeviceResponseType = DeviceResponse.createSimple({
    documents: [document],
    status: 0,
  })
  return response.encodedForOid4Vp
}
