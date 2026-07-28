/**
 * DCQL post-validation — the checks OpenID4VP 1.0 §14.9 requires the verifier to run itself
 * because the wallet's application of query constraints must never be trusted. These checks
 * cannot be disabled by configuration.
 *
 * Two claim-level defects are kept apart on purpose: a requested claim that never arrived
 * fails `dcql.claims_present`, while a claim that arrived with a value of the wrong type
 * (against the preset's declared `claimTypes`) fails `dcql.claim_types_valid` with the
 * received type in the report. Both fail verification; neither is left for claim extraction
 * to stumble over.
 *
 * Scope in this release: `mso_mdoc` presentations are checked claim by claim; a presentation
 * for a `dc+sd-jwt` query is reported through `sdjwt.decoded` as failed (SD-JWT VC verification
 * is not built yet), and `dcql.vct_match` reports `skipped` accordingly.
 */

import { wrongClaimType } from '../presets/claims.js'
import type {
  ClaimTypeExpectation,
  DcqlCredentialQuery,
  DcqlQuery,
  PresetDefinition,
  VerifiedCredential,
} from '../types.js'
import type { CheckCollector } from './checks.js'

export interface PresentedCredential {
  queryId: string
  credential: VerifiedCredential | null
  /** Whether the format-level verification chain (signatures, digests, transcript) passed. */
  chainPassed: boolean
}

/**
 * Runs the DCQL post-validation checks for one response and reports into `collector`. Returns
 * the set of query ids whose presentation fully satisfied the query — the input for the
 * credential-set evaluation.
 */
export function postValidateDcql(
  dcql: DcqlQuery,
  presented: PresentedCredential[],
  collector: CheckCollector,
  claimTypes?: PresetDefinition['claimTypes']
): void {
  const queriesById = new Map<string, DcqlCredentialQuery>(
    dcql.credentials.map((query) => [query.id, query])
  )

  const satisfied = new Set<string>()

  for (const entry of presented) {
    const query = queriesById.get(entry.queryId)
    if (query === undefined) {
      collector.add(
        'dcql.credential_sets_satisfied',
        'failed',
        `the response contains an entry for "${entry.queryId}", which is not a credential ` +
          'query id of this request',
        entry.queryId
      )
      continue
    }
    if (entry.credential === null) continue

    const ok = validateAgainstQuery(query, entry.credential, collector, claimTypes?.[query.id])
    if (ok && entry.chainPassed) satisfied.add(entry.queryId)
  }

  validateCredentialSets(dcql, satisfied, collector)
}

function validateAgainstQuery(
  query: DcqlCredentialQuery,
  credential: VerifiedCredential,
  collector: CheckCollector,
  expected?: Readonly<Record<string, ClaimTypeExpectation>>
): boolean {
  if (query.format === 'mso_mdoc') {
    return validateMdocQuery(query, credential, collector, expected)
  }
  // The claim keys of an SD-JWT credential cannot be validated before SD-JWT verification
  // exists; the format mismatch itself has already been reported via sdjwt.decoded.
  collector.add(
    'dcql.vct_match',
    'skipped',
    'SD-JWT VC verification is not implemented in this release',
    query.id
  )
  return false
}

function validateMdocQuery(
  query: DcqlCredentialQuery,
  credential: VerifiedCredential,
  collector: CheckCollector,
  expected?: Readonly<Record<string, ClaimTypeExpectation>>
): boolean {
  let ok = true

  const expectedDoctype = query.meta.doctype_value
  if (expectedDoctype === undefined) {
    collector.add('dcql.doctype_match', 'skipped', 'the query pins no doctype_value', query.id)
  } else {
    const doctypeOk = credential.docType === expectedDoctype
    collector.add(
      'dcql.doctype_match',
      doctypeOk ? 'passed' : 'failed',
      doctypeOk
        ? `docType "${credential.docType}" matches the query`
        : `presented docType "${credential.docType}" does not match the requested ` +
            `doctype_value "${expectedDoctype}"`,
      query.id
    )
    ok &&= doctypeOk
  }

  const claims = query.claims ?? []
  if (claims.length === 0) {
    collector.add(
      'dcql.claims_present',
      'passed',
      'the query requests no specific claims',
      query.id
    )
    return ok
  }

  // With claim_sets, one fully-present set satisfies the query (OpenID4VP 1.0 §6.4.1);
  // without, every requested claim must be present.
  const presentByClaim = new Map<string, boolean>()
  const missing: string[] = []
  for (const claim of claims) {
    const identifier = mdocElementIdentifier(claim.path)
    const present = identifier !== null && credential.claims[identifier] !== undefined
    if (claim.id !== undefined) presentByClaim.set(claim.id, present)
    if (!present) missing.push(identifier ?? JSON.stringify(claim.path))
  }

  let claimsOk: boolean
  if (query.claim_sets !== undefined && query.claim_sets.length > 0) {
    claimsOk = query.claim_sets.some((set) =>
      set.every((claimId) => presentByClaim.get(claimId) === true)
    )
    collector.add(
      'dcql.claims_present',
      claimsOk ? 'passed' : 'failed',
      claimsOk
        ? 'a full claim set of the query is present in the presentation'
        : 'no claim set of the query is fully present in the presentation',
      query.id
    )
  } else {
    claimsOk = missing.length === 0
    collector.add(
      'dcql.claims_present',
      claimsOk ? 'passed' : 'failed',
      claimsOk
        ? 'every requested data element is present in the presentation'
        : `requested data elements missing from the presentation: ${missing.join(', ')}`,
      query.id
    )
  }
  ok &&= claimsOk

  if (claimsOk) {
    // Claims that arrived must decode to usable values and — where the preset declared an
    // expected type — to values of that type. A mis-issued credential (say, a boolean age flag
    // embedded as text) fails here with the received type in the report, instead of surfacing
    // later as an opaque claim extraction error. Value semantics (is the boolean true, is the
    // person old enough) stay with the caller (preset `extract`).
    const problems: string[] = []
    for (const claim of claims) {
      const identifier = mdocElementIdentifier(claim.path)
      if (identifier === null) continue
      const value = credential.claims[identifier]
      if (value === undefined) continue
      const expectation = expected?.[identifier]
      if (expectation !== undefined && typeof value !== expectation.type) {
        problems.push(
          wrongClaimType(expectation.type, identifier, value, {
            redactValue: expectation.redactValue === true,
          })
        )
      } else if (value === null) {
        problems.push(`"${identifier}" decodes to null`)
      }
    }
    collector.add(
      'dcql.claim_types_valid',
      problems.length === 0 ? 'passed' : 'failed',
      problems.length === 0
        ? 'every presented data element decodes to a usable value'
        : problems.join('; '),
      query.id
    )
    ok &&= problems.length === 0
  } else {
    collector.add(
      'dcql.claim_types_valid',
      'skipped',
      'not evaluated: requested data elements are missing (dcql.claims_present)',
      query.id
    )
  }

  return ok
}

/**
 * An mdoc claims-path pointer must be exactly `[namespace, dataElementIdentifier]`
 * (OpenID4VP 1.0 Appendix B.2.3); the flattened claim key is the element identifier.
 */
function mdocElementIdentifier(path: Array<string | number | null>): string | null {
  if (path.length !== 2) return null
  const identifier = path[1]
  return typeof identifier === 'string' ? identifier : null
}

function validateCredentialSets(
  dcql: DcqlQuery,
  satisfied: Set<string>,
  collector: CheckCollector
): void {
  const sets = dcql.credential_sets
  if (sets === undefined || sets.length === 0) {
    // Without credential_sets every credential query must be satisfied (OpenID4VP 1.0 §6.4.2).
    const unsatisfied = dcql.credentials.map((query) => query.id).filter((id) => !satisfied.has(id))
    collector.add(
      'dcql.credential_sets_satisfied',
      unsatisfied.length === 0 ? 'passed' : 'failed',
      unsatisfied.length === 0
        ? 'every credential query of the request is satisfied'
        : `credential queries not satisfied by the response: ${unsatisfied.join(', ')}`
    )
    return
  }

  const failing = sets
    .filter((set) => set.required !== false)
    .filter((set) => !set.options.some((option) => option.every((id) => satisfied.has(id))))
  collector.add(
    'dcql.credential_sets_satisfied',
    failing.length === 0 ? 'passed' : 'failed',
    failing.length === 0
      ? 'every required credential set has a fully satisfied option'
      : 'a required credential set has no fully satisfied option in the response'
  )
}
