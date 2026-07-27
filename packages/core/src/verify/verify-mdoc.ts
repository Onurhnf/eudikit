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
 * Today's AV attestations are short-lived and carry no status entry, so there is nothing to
 * fetch; status-list checking arrives when a credential population that uses it does.
 */

import { DeviceResponse, type Document, Verifier } from '@owf/mdoc'
import type { TrustedListSnapshot } from '../trust/trusted-list.js'
import type { Check, VerifiedCredential } from '../types.js'
import { certificateBytesEqual } from './certificates.js'
import { CheckCollector, mapAssessment } from './checks.js'
import { jsonSafeClaims } from './json-safe.js'
import { createMdocContext } from './mdoc-context.js'

const ALLOWED_ISSUER_ALGORITHMS = new Set([-7, -35, -36])

export interface MdocTrustOptions {
  /** DER trust anchors for DS-direct-match. */
  anchors: Uint8Array[]
  /** The AV trusted list snapshot for this verification; `null` when the layer is disabled. */
  trustedList: TrustedListSnapshot | null
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

  // The chain check runs against the union of the configured anchors and every trusted-list
  // certificate: a DS on the list and a DS chained to a bring-your-own anchor are both
  // acceptable issuers (list membership itself is judged separately below).
  const trustedCertificates = [
    ...input.trust.anchors,
    ...(input.trust.trustedList?.services.flatMap((service) => service.certificates) ?? []),
  ]

  try {
    await Verifier.verifyDeviceResponse(
      {
        deviceResponse,
        sessionTranscript: input.sessionTranscript,
        trustedCertificates: [{ issuance: trustedCertificates }],
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

  const trustedListEntry = evaluateTrustedListMembership(
    input.trust,
    document.issuerSigned.issuerAuth.certificate,
    collector,
    queryId
  )
  if (credential !== null && trustedListEntry !== null) {
    credential.issuer.trustedListEntry = trustedListEntry
  }

  collector.add(
    'mdoc.status_list_valid',
    'skipped',
    'revocation is not checked in this release: AV attestations are short-lived and carry ' +
      'no status entry',
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
      // Filled in after the trusted-list membership evaluation runs.
      trustedListEntry: null,
    },
    validity: {
      validFrom: validity.validFrom,
      validUntil: validity.validUntil,
      signedAt: validity.signed,
    },
  }
}

/**
 * DS-direct-match against the AV trusted list: the presented signer certificate must be
 * byte-equal to a `ServiceDigitalIdentity` certificate (every identity on the list IS a DS
 * certificate — there is no chain to build). Status semantics: only `recognized` passes;
 * `deprecated` (and any future status) fails, strictly in strict mode and as a warning in
 * permissive mode. A DS that is absent from the list but accepted through
 * `additionalTrustAnchors` reports `skipped` — membership was evaluated and is honestly "no",
 * but the union contract says configured anchors may vouch instead (`trust.chain_valid`).
 */
function evaluateTrustedListMembership(
  trust: MdocTrustOptions,
  signerCertificate: Uint8Array | undefined,
  collector: CheckCollector,
  queryId: string
): VerifiedCredential['issuer']['trustedListEntry'] {
  if (trust.trustedList === null) {
    collector.add(
      'trust.issuer_in_trusted_list',
      'skipped',
      'the AV trusted list layer is disabled; issuer trust rests on additionalTrustAnchors ' +
        '(trust.chain_valid)',
      queryId
    )
    return null
  }
  if (!trust.trustedList.available) {
    collector.add(
      'trust.issuer_in_trusted_list',
      'skipped',
      'membership could not be evaluated: the trusted list is unavailable (trust.list_fresh)',
      queryId
    )
    return null
  }
  if (signerCertificate === undefined) {
    collector.add(
      'trust.issuer_in_trusted_list',
      'failed',
      'the presentation carries no document signer certificate to match against the list',
      queryId
    )
    return null
  }

  for (const service of trust.trustedList.services) {
    for (const certificate of service.certificates) {
      if (!certificateBytesEqual(certificate, signerCertificate)) continue
      const recognized = service.status === 'recognized'
      collector.add(
        'trust.issuer_in_trusted_list',
        recognized ? 'passed' : 'failed',
        recognized
          ? `DS certificate matches "${service.serviceName}" (${service.tspName})`
          : `DS certificate matches "${service.serviceName}" (${service.tspName}) but the ` +
              `service status is "${service.status}" — only recognized services are trusted`,
        queryId
      )
      return {
        tspName: service.tspName,
        serviceName: service.serviceName,
        status: service.status,
      }
    }
  }

  const anchorsVouch =
    trust.anchors.length > 0 &&
    !collector.checks.some((check) => check.id === 'trust.chain_valid' && check.status === 'failed')
  collector.add(
    'trust.issuer_in_trusted_list',
    anchorsVouch ? 'skipped' : 'failed',
    anchorsVouch
      ? 'not on the AV trusted list; the issuer is accepted through additionalTrustAnchors ' +
          '(trust.chain_valid)'
      : 'the document signer certificate matches no ServiceDigitalIdentity on the AV trusted list',
    queryId
  )
  return null
}

function flattenDn(subject: string): string {
  return subject.split('\n').join(', ')
}

function briefly(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause)
}
