/**
 * The response-side engine: takes a parsed `vp_token`, the session's binding material and the
 * trust policy, runs the per-presentation verification chains plus the DCQL post-validation,
 * and produces the final `VerificationResult`.
 *
 * The verdict rule is strict by construction: any failed check fails the result. The single,
 * deliberate exception is `trust.*` under `mode: 'permissive'`, where trust-class failures are
 * reported but not enforced — for testbeds whose local issuers are on no trusted list. The
 * result's `policy` field always names the mode that produced it, so a permissive pass can
 * never masquerade as a strict one. Signature, digest, transcript and DCQL checks are enforced
 * in every mode.
 */

import type { TrustedListSnapshot, TrustedListSource } from '../trust/trusted-list.js'
import type {
  Check,
  DcqlQuery,
  PresetDefinition,
  VerificationResult,
  VerifiedCredential,
  WalletProfile,
} from '../types.js'
import { EudikitError } from '../types.js'
import { CheckCollector } from './checks.js'
import { type PresentedCredential, postValidateDcql } from './dcql-match.js'
import { verifyMdocPresentation } from './verify-mdoc.js'

export interface ResolvedTrust {
  mode: 'strict' | 'permissive'
  /** DER trust anchors (from `trust.additionalTrustAnchors`). */
  anchors: Uint8Array[]
  /** `null` when `avTrustedList: false` — trust then rests on `additionalTrustAnchors` alone. */
  trustedList: TrustedListSource | null
}

export interface EngineInput {
  /** Parsed `vp_token`: query id → one or more encoded presentations. */
  vpToken: Record<string, string[]>
  dcql: DcqlQuery
  /** Encoded `SessionTranscript` the wallet must have signed over. */
  sessionTranscript: Uint8Array
  trust: ResolvedTrust
  profile: WalletProfile
  sessionId: string
  now: Date
  /** Checks accumulated before the engine ran (session/envelope class). */
  baseChecks: Check[]
  /** Preset that created the request, when its definition is known to this instance. */
  preset?: PresetDefinition<unknown>
}

export async function runVerification(input: EngineInput): Promise<VerificationResult> {
  const collector = new CheckCollector()
  collector.checks.push(...input.baseChecks)

  const trustedList =
    input.trust.trustedList === null ? null : await input.trust.trustedList.getSnapshot(input.now)
  addTrustedListChecks(collector, trustedList)

  const queriesById = new Map(input.dcql.credentials.map((query) => [query.id, query]))
  const presented: PresentedCredential[] = []

  for (const [queryId, presentations] of Object.entries(input.vpToken)) {
    const query = queriesById.get(queryId)

    if (presentations.length !== 1) {
      // `multiple` is never requested by this release, so the spec fixes the array length at
      // exactly one; extra entries are reported and only the first is evaluated.
      collector.add(
        'dcql.credential_sets_satisfied',
        'failed',
        `vp_token entry "${queryId}" carries ${presentations.length} presentations where ` +
          'exactly one is allowed',
        queryId
      )
    }
    const presentation = presentations[0]
    if (presentation === undefined) continue

    if (query !== undefined && query.format === 'dc+sd-jwt') {
      collector.add(
        'sdjwt.decoded',
        'failed',
        'SD-JWT VC verification is not implemented in this release; this presentation cannot ' +
          'be accepted',
        queryId
      )
      presented.push({ queryId, credential: null, chainPassed: false })
      continue
    }

    const outcome = await verifyMdocPresentation({
      queryId,
      presentation,
      sessionTranscript: input.sessionTranscript,
      trust: { anchors: input.trust.anchors, trustedList },
      now: input.now,
    })
    collector.checks.push(...outcome.checks)
    presented.push({
      queryId,
      credential: outcome.credential,
      chainPassed: chainPassed(outcome.checks, input.trust.mode),
    })
  }

  postValidateDcql(input.dcql, presented, collector)

  const enforcedFailures = collector.checks.filter(
    (check) => check.status === 'failed' && enforced(check, input.trust.mode)
  )
  const verified = enforcedFailures.length === 0

  const credentials = presented
    .map((entry) => entry.credential)
    .filter((credential): credential is VerifiedCredential => credential !== null)

  let claims: unknown = null
  let error: EudikitError | null = verified
    ? null
    : verdictError(enforcedFailures, trustedList, input.trust.mode)

  if (verified && input.preset !== undefined) {
    try {
      claims = input.preset.extract(credentials)
    } catch (cause) {
      claims = null
      error =
        cause instanceof EudikitError
          ? cause
          : new EudikitError('PRESENTATION_MALFORMED', 'preset claim extraction failed', {
              cause,
            })
    }
  }

  return {
    verified: verified && error === null,
    profile: input.profile,
    policy: input.trust.mode,
    // Preset outputs are arbitrary shapes behind the TClaims generic; the default surface
    // narrows them to the record type.
    claims: claims as Record<string, unknown> | null,
    credentials,
    diagnostics: collector.checks,
    error,
    sessionId: input.sessionId,
  }
}

/** Whether a failed check fails the verdict under the given trust mode. */
function enforced(check: Check, mode: 'strict' | 'permissive'): boolean {
  if (mode === 'strict') return true
  return !check.id.startsWith('trust.')
}

/**
 * Whether one presentation's chain checks all passed — the per-credential input to the
 * credential-set evaluation. Under permissive trust, trust-class failures do not disqualify
 * the credential (that is the whole point of the mode).
 */
function chainPassed(checks: Check[], mode: 'strict' | 'permissive'): boolean {
  return !checks.some((check) => check.status === 'failed' && enforced(check, mode))
}

function verdictMessage(failures: Check[]): string {
  const ids = [...new Set(failures.map((check) => check.id))]
  const shown = ids.slice(0, 4).join(', ')
  const suffix = ids.length > 4 ? ` and ${ids.length - 4} more` : ''
  return `verification failed: ${shown}${suffix} — see diagnostics for the full report`
}

/**
 * A rejection caused purely by an unreachable trusted list gets its own error code — the
 * operator's remedy (network/cache) is different from a wallet or credential problem. Any
 * non-trust failure in the mix means the presentation itself has a problem, and the generic
 * verdict wins.
 */
function verdictError(
  failures: Check[],
  trustedList: TrustedListSnapshot | null,
  mode: 'strict' | 'permissive'
): EudikitError {
  const listUnavailable = trustedList !== null && !trustedList.available
  if (
    listUnavailable &&
    mode === 'strict' &&
    failures.every((check) => check.id.startsWith('trust.'))
  ) {
    return new EudikitError(
      'TRUSTED_LIST_UNAVAILABLE',
      'the AV trusted list could not be fetched and no cached copy exists, so strict mode ' +
        'cannot decide issuer trust — see diagnostics (trust.list_fresh) for the fetch failure'
    )
  }
  return new EudikitError('VERIFICATION_FAILED', verdictMessage(failures))
}

/**
 * The per-result trusted-list rows. Freshness is loud in both directions: a stale or missing
 * list is a failed `trust.list_fresh` (a trust-class check — strict rejects, permissive
 * warns), never a silent fallback. The list's own XAdES signature is out of scope for this
 * release, reported as skipped rather than omitted.
 */
function addTrustedListChecks(
  collector: CheckCollector,
  trustedList: TrustedListSnapshot | null
): void {
  if (trustedList === null) {
    collector.add(
      'trust.list_fresh',
      'skipped',
      'the AV trusted list layer is disabled (avTrustedList: false)'
    )
    collector.add('trust.list_signature_valid', 'skipped', 'no trusted list in use')
    return
  }
  collector.add(
    'trust.list_fresh',
    trustedList.available && trustedList.fresh ? 'passed' : 'failed',
    trustedList.detail
  )
  collector.add(
    'trust.list_signature_valid',
    'skipped',
    'the trusted list XML signature (XAdES) is not verified in this release; transport ' +
      'integrity rests on HTTPS'
  )
}
