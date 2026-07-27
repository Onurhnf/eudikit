/**
 * Internal DCQL construction helpers (OpenID4VP 1.0 §6).
 *
 * The presets assemble their queries through these functions so that every emitted query has
 * passed the same structural checks. The checks are deliberately light — identifier syntax and
 * referential integrity, not a full schema: query construction is our own code, and format-level
 * validity is pinned in tests by cross-validating every produced query with the `dcql` package.
 */

import type { DcqlCredentialQuery, DcqlQuery } from '../types.js'
import { EudikitError } from '../types.js'

/** OpenID4VP 1.0 §6: credential and claim ids are non-empty `[A-Za-z0-9_-]` strings. */
const ID_PATTERN = /^[A-Za-z0-9_-]+$/

export interface MdocClaimSpec {
  id?: string
  path: [namespace: string, dataElementIdentifier: string]
  /**
   * Defaults to `false` and is always emitted: the explicit value tells the wallet (and its
   * consent UI) that the verifier does not intend to store the element (ISO 18013-5 §8.3.2.1.2.1).
   */
  intentToRetain?: boolean
}

export interface SdJwtClaimSpec {
  id?: string
  path: Array<string | number | null>
}

function invalid(detail: string): never {
  throw new EudikitError('CONFIG_INVALID', `invalid DCQL query: ${detail}`)
}

/** Credential query for an ISO mdoc (`mso_mdoc`) document. */
export function mdocCredentialQuery(input: {
  id: string
  doctype: string
  claims: MdocClaimSpec[]
  claimSets?: string[][]
}): DcqlCredentialQuery {
  return {
    id: input.id,
    format: 'mso_mdoc',
    meta: { doctype_value: input.doctype },
    claims: input.claims.map((claim) => ({
      ...(claim.id !== undefined ? { id: claim.id } : {}),
      path: claim.path,
      intent_to_retain: claim.intentToRetain ?? false,
    })),
    ...(input.claimSets !== undefined ? { claim_sets: input.claimSets } : {}),
  }
}

/** Credential query for an IETF SD-JWT VC (`dc+sd-jwt`) credential. */
export function sdJwtCredentialQuery(input: {
  id: string
  vctValues: string[]
  claims: SdJwtClaimSpec[]
  claimSets?: string[][]
}): DcqlCredentialQuery {
  if (input.vctValues.length === 0) invalid(`credential "${input.id}" has empty vct_values`)
  return {
    id: input.id,
    format: 'dc+sd-jwt',
    meta: { vct_values: input.vctValues },
    claims: input.claims.map((claim) => ({
      ...(claim.id !== undefined ? { id: claim.id } : {}),
      path: claim.path,
    })),
    ...(input.claimSets !== undefined ? { claim_sets: input.claimSets } : {}),
  }
}

/**
 * Assembles credential queries and credential-set options into a `DcqlQuery`, enforcing the
 * structural invariants of OpenID4VP 1.0 §6:
 *
 *  - at least one credential query; ids are well-formed and unique;
 *  - claim ids are well-formed and unique within their query;
 *  - `claim_sets` only where `claims` exist, every claim carries an id, and every referenced
 *    claim id is defined;
 *  - every id in `credential_sets[].options` refers to a defined credential query.
 */
export function buildDcqlQuery(
  credentials: DcqlCredentialQuery[],
  credentialSets?: Array<{ options: string[][]; required?: boolean }>
): DcqlQuery {
  if (credentials.length === 0) invalid('a query needs at least one credential query')

  const credentialIds = new Set<string>()
  for (const credential of credentials) {
    if (!ID_PATTERN.test(credential.id)) invalid(`credential id "${credential.id}" is malformed`)
    if (credentialIds.has(credential.id)) invalid(`duplicate credential id "${credential.id}"`)
    credentialIds.add(credential.id)
    validateClaims(credential)
  }

  if (credentialSets !== undefined) {
    for (const set of credentialSets) {
      if (set.options.length === 0) invalid('a credential set needs at least one option')
      for (const option of set.options) {
        for (const id of option) {
          if (!credentialIds.has(id)) {
            invalid(`credential set option references unknown credential id "${id}"`)
          }
        }
      }
    }
  }

  return {
    credentials,
    ...(credentialSets !== undefined ? { credential_sets: credentialSets } : {}),
  }
}

function validateClaims(credential: DcqlCredentialQuery): void {
  const { id, claims, claim_sets: claimSets } = credential

  if (claims !== undefined && claims.length === 0) {
    invalid(`credential "${id}" has an empty claims array`)
  }

  const claimIds = new Set<string>()
  for (const claim of claims ?? []) {
    if (claim.path.length === 0) invalid(`credential "${id}" has a claim with an empty path`)
    if (claim.id === undefined) continue
    if (!ID_PATTERN.test(claim.id)) invalid(`claim id "${claim.id}" in "${id}" is malformed`)
    if (claimIds.has(claim.id)) invalid(`duplicate claim id "${claim.id}" in "${id}"`)
    claimIds.add(claim.id)
  }

  if (claimSets === undefined) return
  if (claims === undefined) invalid(`credential "${id}" has claim_sets but no claims`)
  if (claimIds.size !== (claims ?? []).length) {
    invalid(`credential "${id}" uses claim_sets, so every claim needs an id`)
  }
  for (const set of claimSets) {
    for (const claimId of set) {
      if (!claimIds.has(claimId)) {
        invalid(`claim set in "${id}" references unknown claim id "${claimId}"`)
      }
    }
  }
}
