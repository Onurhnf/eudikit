/**
 * Verification of a single mdoc presentation (one base64url `DeviceResponse` out of a
 * `vp_token` entry) against the session's transcript and trust anchors.
 *
 * The heavy lifting — issuer signature, value digests, device signature over the
 * SessionTranscript, certificate chain — runs inside `@owf/mdoc`'s verifier with our production
 * context; its assessments are translated into the `Check` taxonomy. Around that core this
 * module adds the checks the upstream library does not perform: response status, doctype
 * consistency, device-key authorization, and the issuer-algorithm allowlist.
 *
 * Revocation is deliberately not fetched here: `mdoc.status_list_valid` reports `skipped`.
 * Status-list checking requires outbound fetches and a caching policy, both of which arrive
 * with the trusted-list layer; today's AV attestations are short-lived and the EU list carries
 * no revocation entries for them.
 */

import { DeviceResponse, type Document, Verifier } from '@owf/mdoc'
import type { Check, VerifiedCredential } from '../types.js'
import { CheckCollector, mapAssessment } from './checks.js'
import { jsonSafeClaims } from './json-safe.js'
import { createMdocContext } from './mdoc-context.js'

const ALLOWED_ISSUER_ALGORITHMS = new Set([-7, -35, -36])

export interface MdocTrustOptions {
  /** DER trust anchors for DS-direct-match. */
  anchors: Uint8Array[]
}

export interface VerifyMdocInput {
  /** DCQL credential query id this presentation answers. */
  queryId: string
  /** base64url-encoded `DeviceResponse` CBOR. */
  presentation: string
  /** Encoded `SessionTranscript` bytes the wallet must have signed over. */
  sessionTranscript: Uint8Array
  trust: MdocTrustOptions
  now: Date
}

export interface VerifyMdocOutput {
  /** Extracted credential — present even when checks failed, so diagnostics stay inspectable; `null` only when decoding failed. */
  credential: VerifiedCredential | null
  checks: Check[]
}

/** Stateless — one shared instance serves every verification. */
const ctx = createMdocContext()

export async function verifyMdocPresentation(input: VerifyMdocInput): Promise<VerifyMdocOutput> {
  const collector = new CheckCollector()
  const { queryId } = input

  let deviceResponse: DeviceResponse
  try {
    deviceResponse = DeviceResponse.fromEncodedForOid4Vp(input.presentation)
  } catch (cause) {
    collector.add(
      'mdoc.decoded',
      'failed',
      `presentation is not a base64url CBOR DeviceResponse: ${briefly(cause)}`,
      queryId
    )
    return { credential: null, checks: collector.checks }
  }
  collector.add('mdoc.decoded', 'passed', 'DeviceResponse decoded', queryId)

  collector.add(
    'mdoc.response_status_ok',
    deviceResponse.status === 0 ? 'passed' : 'failed',
    `DeviceResponse status is ${deviceResponse.status} (0 = OK, ISO 18013-5 table 8)`,
    queryId
  )

  const document = deviceResponse.documents?.[0]
  if (document === undefined) {
    collector.add(
      'mdoc.issuer_auth_present',
      'failed',
      'DeviceResponse carries no document',
      queryId
    )
    return { credential: null, checks: collector.checks }
  }
  if ((deviceResponse.documents?.length ?? 0) > 1) {
    collector.add(
      'mdoc.decoded',
      'failed',
      'DeviceResponse carries more than one document where the query allows one; only the ' +
        'first is evaluated',
      queryId
    )
  }

  let credential: VerifiedCredential | null = null
  try {
    credential = extractCredential(document, queryId, collector)
  } catch (cause) {
    collector.add('mdoc.issuer_auth_present', 'failed', briefly(cause), queryId)
    return { credential: null, checks: collector.checks }
  }

  try {
    await Verifier.verifyDeviceResponse(
      {
        deviceResponse,
        sessionTranscript: input.sessionTranscript,
        trustedCertificates: [{ issuance: input.trust.anchors }],
        now: input.now,
        disableStatusValidation: true,
        onCheck: (assessment) => {
          collector.checks.push(mapAssessment(assessment, queryId))
        },
      },
      ctx
    )
  } catch (cause) {
    // The upstream verifier reports through onCheck and rarely throws; a throw here means a
    // malformed structure deep in the CBOR, which no later check would have covered.
    collector.add('mdoc.decoded', 'failed', `verification aborted: ${briefly(cause)}`, queryId)
  }

  collector.add(
    'mdoc.status_list_valid',
    'skipped',
    'revocation is not checked in this release: status-list fetching lands with the ' +
      'trusted-list layer, and AV attestations carry no status entry',
    queryId
  )

  // The device signature was verified against the MSO's own deviceKeyInfo.deviceKey, so a valid
  // signature is itself the proof that the presenting device holds the issuer-attested key.
  const deviceSignatureOk = collector.checks.some(
    (check) => check.id === 'mdoc.device_signature_valid' && check.status === 'passed'
  )
  collector.add(
    'mdoc.device_key_matches_mso',
    deviceSignatureOk ? 'passed' : 'failed',
    deviceSignatureOk
      ? 'device authentication verified against the deviceKey attested in the MSO'
      : 'device authentication did not verify against the deviceKey attested in the MSO',
    queryId
  )

  return { credential, checks: collector.checks }
}

/**
 * Reads document metadata and claims, and performs the structural checks upstream leaves to the
 * caller: doctype consistency, issuer algorithm allowlist, and device-key authorization for
 * device-signed elements.
 */
function extractCredential(
  document: Document,
  queryId: string,
  collector: CheckCollector
): VerifiedCredential {
  const issuerAuth = document.issuerSigned.issuerAuth
  collector.add('mdoc.issuer_auth_present', 'passed', undefined, queryId)

  let chainParsed = true
  let issuerSubject = ''
  try {
    const chain = issuerAuth.certificateChain
    if (chain.length === 0) throw new Error('x5chain header is empty')
    issuerSubject = flattenDn(
      (
        ctx.x509.getCertificateData({ certificate: issuerAuth.certificate }) as {
          subjectName: string
        }
      ).subjectName
    )
  } catch (cause) {
    chainParsed = false
    collector.add('mdoc.issuer_chain_parsed', 'failed', briefly(cause), queryId)
  }
  if (chainParsed) {
    collector.add('mdoc.issuer_chain_parsed', 'passed', undefined, queryId)
  }

  const algorithm = issuerAuth.algorithm
  collector.add(
    'mdoc.issuer_key_algorithm_allowed',
    typeof algorithm === 'number' && ALLOWED_ISSUER_ALGORITHMS.has(algorithm) ? 'passed' : 'failed',
    `issuerAuth alg ${String(algorithm)}; allowed: ES256 (-7), ES384 (-35), ES512 (-36)`,
    queryId
  )

  const mso = issuerAuth.mobileSecurityObject
  collector.add(
    'mdoc.doctype_consistent',
    document.docType === mso.docType ? 'passed' : 'failed',
    document.docType === mso.docType
      ? `document and MSO agree on docType "${document.docType}"`
      : `document docType "${document.docType}" != MSO docType "${mso.docType}"`,
    queryId
  )

  // The upstream verifier reports a missing deviceAuth as a failure but stays silent when one
  // is present; the passed row is added here so the report is complete either way.
  const deviceAuth = document.deviceSigned.deviceAuth
  if (deviceAuth.deviceSignature !== undefined || deviceAuth.deviceMac !== undefined) {
    collector.add(
      'mdoc.device_signed_present',
      'passed',
      deviceAuth.deviceSignature !== undefined
        ? 'deviceAuth carries a DeviceSignature'
        : 'deviceAuth carries a DeviceMac',
      queryId
    )
  }

  // Device-signed data elements need an explicit keyAuthorizations grant (ISO 18013-5
  // §9.1.2.4); with no device-signed elements there is nothing to authorize.
  const deviceNamespaces = document.deviceSigned.deviceNamespaces.deviceNamespaces
  if (deviceNamespaces.size === 0) {
    collector.add(
      'mdoc.device_key_authorized',
      'passed',
      'no device-signed data elements, nothing to authorize',
      queryId
    )
  } else {
    const authorizations = mso.deviceKeyInfo.keyAuthorizations
    const authorizedNamespaces = new Set(authorizations?.namespaces ?? [])
    const unauthorized = [...deviceNamespaces.keys()].filter(
      (namespace) => !authorizedNamespaces.has(namespace)
    )
    collector.add(
      'mdoc.device_key_authorized',
      unauthorized.length === 0 ? 'passed' : 'failed',
      unauthorized.length === 0
        ? 'all device-signed namespaces are authorized by the MSO keyAuthorizations'
        : `device-signed namespaces without a keyAuthorizations grant: ${unauthorized.join(', ')}`,
      queryId
    )
  }

  const claims: Record<string, unknown> = {}
  for (const [, items] of document.issuerSigned.issuerNamespaces.issuerNamespaces) {
    for (const item of items) {
      claims[item.elementIdentifier] = item.elementValue
    }
  }

  const validity = mso.validityInfo
  return {
    queryId,
    format: 'mso_mdoc',
    docType: document.docType,
    claims: jsonSafeClaims(claims),
    issuer: {
      subject: issuerSubject,
      // Populated when the trusted-list layer lands; DS-direct-match has no TSP metadata.
      trustedListEntry: null,
    },
    validity: {
      validFrom: validity.validFrom,
      validUntil: validity.validUntil,
      signedAt: validity.signed,
    },
  }
}

function flattenDn(subject: string): string {
  return subject.split('\n').join(', ')
}

function briefly(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause)
}
