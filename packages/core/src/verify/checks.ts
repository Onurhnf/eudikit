/**
 * The bridge between `@owf/mdoc`'s free-text verification assessments and our stable `Check`
 * taxonomy. Every upstream assessment becomes one `Check` row — several upstream rows may share
 * a `CheckId` (e.g. the per-element digest comparisons all land on `mdoc.value_digests_valid`),
 * which keeps the full granularity in `detail` without inventing new public ids.
 */

import type { VerificationAssessment } from '@owf/mdoc'
import type { Check, CheckId } from '../types.js'

export class CheckCollector {
  readonly checks: Check[] = []

  add(id: CheckId, status: Check['status'], detail?: string, credentialId?: string): void {
    this.checks.push({
      id,
      status,
      ...(detail !== undefined ? { detail } : {}),
      ...(credentialId !== undefined ? { credentialId } : {}),
    })
  }
}

/**
 * Exact-match table for the assessments `@owf/mdoc` 0.7 emits. Checked before the prefix rules
 * and the per-category fallback.
 */
const EXACT: Record<string, CheckId> = {
  'Device Response must include "version" element.': 'mdoc.decoded',
  'Device Response must not include documents or at least one document.': 'mdoc.decoded',
  'Device Auth must contain a deviceSignature or deviceMac element': 'mdoc.device_signed_present',
  'No Device Signature or Device Mac found on Device Auth': 'mdoc.device_signed_present',
  'Device signature must be valid': 'mdoc.device_signature_valid',
  'Device MAC must use alg 5 (HMAC 256/256)': 'mdoc.device_signature_valid',
  'Ephemeral private key must be present when using MAC authentication':
    'mdoc.device_signature_valid',
  'Device MAC must be valid': 'mdoc.device_signature_valid',
  "Country name (C) must be present in the issuer certificate's subject distinguished name":
    'mdoc.issuer_chain_parsed',
  'Issuer certificate must be valid': 'trust.chain_valid',
  'Status information must be valid': 'mdoc.status_list_valid',
  'Issuer auth signature is invalid': 'mdoc.issuer_signature_valid',
  'The MSO signed date must be within the validity period of the certificate':
    'mdoc.validity_window',
  'The MSO must be valid at the time of verification': 'mdoc.validity_window',
  // Chain determination against the anchor set (anchors ∪ trusted-list certificates) is
  // `trust.chain_valid`; `trust.issuer_in_trusted_list` is reserved for the byte-equality
  // membership decision made in verify-mdoc.
  'Unable to determine a trusted issuance chain for the provided trusted certificates and the signer of the issuer auth':
    'trust.chain_valid',
  'Issuer Auth must include a supported digestAlgorithm element': 'mdoc.value_digests_valid',
}

const PREFIXES: Array<{ prefix: string; id: CheckId }> = [
  { prefix: 'Issuer Auth must include digests for namespace', id: 'mdoc.value_digests_valid' },
  { prefix: 'The calculated digest for ', id: 'mdoc.value_digests_valid' },
  { prefix: "The 'issuing_country'", id: 'mdoc.issuer_chain_parsed' },
  { prefix: "The 'issuing_jurisdiction'", id: 'mdoc.issuer_chain_parsed' },
  { prefix: 'Device Response did ', id: 'mdoc.decoded' },
]

/**
 * Assessments whose upstream `reason` interpolates presented element values. The taxonomy
 * promise is that `detail` never carries claim values, so these reasons are dropped.
 */
const PII_REASON_PREFIXES = ["The 'issuing_country'", "The 'issuing_jurisdiction'"]

const CATEGORY_FALLBACK: Record<VerificationAssessment['category'], CheckId> = {
  DOCUMENT_FORMAT: 'mdoc.decoded',
  DEVICE_AUTH: 'mdoc.device_signature_valid',
  ISSUER_AUTH: 'mdoc.issuer_signature_valid',
  DATA_INTEGRITY: 'mdoc.value_digests_valid',
  READER_AUTH: 'mdoc.decoded',
}

function checkIdFor(assessment: VerificationAssessment): CheckId {
  const exact = EXACT[assessment.check]
  if (exact !== undefined) return exact
  for (const { prefix, id } of PREFIXES) {
    if (assessment.check.startsWith(prefix)) return id
  }
  return CATEGORY_FALLBACK[assessment.category]
}

export function mapAssessment(assessment: VerificationAssessment, credentialId?: string): Check {
  const dropReason = PII_REASON_PREFIXES.some((prefix) => assessment.check.startsWith(prefix))
  const detail =
    assessment.reason !== undefined && assessment.reason !== assessment.check && !dropReason
      ? `${assessment.check}: ${assessment.reason}`
      : assessment.check
  return {
    id: checkIdFor(assessment),
    // Upstream's WARNING level has no counterpart in the passed/failed/skipped triple; it is
    // reported as skipped so it can neither fail a strict verdict nor pose as a pass.
    status:
      assessment.status === 'PASSED'
        ? 'passed'
        : assessment.status === 'FAILED'
          ? 'failed'
          : 'skipped',
    detail,
    ...(credentialId !== undefined ? { credentialId } : {}),
  }
}
