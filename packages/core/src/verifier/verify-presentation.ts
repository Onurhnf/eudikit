/**
 * `verifier.verifyPresentation()` — session-less, low-level verification for testbeds and
 * debugging. The caller supplies the binding material (`nonce`, and either the `responseUri`
 * of a redirect/QR exchange or the `origin` of a DC API exchange); nothing is read from or
 * written to the session store, so this is NOT replay-protected and must not stand in for the
 * production flow.
 *
 * `mso_mdoc` is fully implemented; `dc+sd-jwt` still throws `notImplemented`.
 */

import { notImplemented } from '../internal/not-implemented.js'
import {
  buildOpenID4VPDCAPISessionTranscript,
  buildOpenID4VPSessionTranscript,
} from '../mdoc/session-transcript.js'
import type { CredentialFormat, DcqlQuery, VerificationResult } from '../types.js'
import { EudikitError } from '../types.js'
import { runVerification } from '../verify/engine.js'
import type { ResolvedVerifierConfig } from './config.js'

export interface VerifyPresentationInput {
  format: CredentialFormat
  /** `mso_mdoc`: base64url DeviceResponse; `dc+sd-jwt`: compact SD-JWT+KB string. */
  presentation: string
  bindings: { nonce: string; origin?: string; clientId?: string; responseUri?: string }
  dcql?: DcqlQuery
}

/** Query id used when no DCQL query is supplied to bind the presentation to. */
const AD_HOC_QUERY_ID = 'presentation'

export async function verifyPresentation(
  config: ResolvedVerifierConfig,
  input: VerifyPresentationInput
): Promise<VerificationResult> {
  if (input.format === 'dc+sd-jwt') {
    notImplemented('verifyPresentation for dc+sd-jwt (SD-JWT VC verification)')
  }
  if (input.format !== 'mso_mdoc') {
    throw new EudikitError(
      'CONFIG_INVALID',
      `verifyPresentation format must be 'mso_mdoc' or 'dc+sd-jwt', got ${JSON.stringify(input.format)}`
    )
  }
  if (typeof input.presentation !== 'string' || input.presentation === '') {
    throw new EudikitError('CONFIG_INVALID', 'verifyPresentation needs a presentation string')
  }

  const bindings = input.bindings
  if (typeof bindings !== 'object' || bindings === null || typeof bindings.nonce !== 'string') {
    throw new EudikitError('CONFIG_INVALID', 'verifyPresentation needs bindings with a nonce')
  }

  // The transcript decides which exchange this presentation is checked against: a responseUri
  // selects the redirect/QR handover, an origin selects the DC API handover. Both unencrypted
  // (jwkThumbprint null) — encrypted flows always run through the session-based entry points.
  let sessionTranscript: Uint8Array
  if (bindings.responseUri !== undefined) {
    sessionTranscript = buildOpenID4VPSessionTranscript({
      clientId: bindings.clientId ?? `redirect_uri:${bindings.responseUri}`,
      nonce: bindings.nonce,
      jwkThumbprint: null,
      responseUri: bindings.responseUri,
    })
  } else if (bindings.origin !== undefined) {
    sessionTranscript = buildOpenID4VPDCAPISessionTranscript({
      origin: bindings.origin,
      nonce: bindings.nonce,
      jwkThumbprint: null,
    })
  } else {
    throw new EudikitError(
      'CONFIG_INVALID',
      'verifyPresentation bindings need a responseUri (redirect/QR exchange) or an origin ' +
        '(DC API exchange) — without one no SessionTranscript can be built and the device ' +
        'signature cannot be checked'
    )
  }

  const dcql = input.dcql ?? adHocQuery()
  const queryId = firstMdocQueryId(dcql) ?? AD_HOC_QUERY_ID

  const result = await runVerification({
    vpToken: { [queryId]: [input.presentation] },
    dcql,
    sessionTranscript,
    trust: config.trust,
    profile: config.profile,
    // No session exists on this path; the empty id makes that visible instead of inventing one.
    sessionId: '',
    now: config.now(),
    baseChecks: [
      {
        id: 'session.found',
        status: 'skipped',
        detail: 'verifyPresentation is session-less; nonce/replay protection is the caller’s',
      },
    ],
  })
  return result
}

/**
 * Without a caller query the presentation is still fully chain-verified; the DCQL layer then
 * has nothing to compare against, so a permissive placeholder query (any docType, no claims)
 * keeps the dcql checks meaningful instead of failing vacuously.
 */
function adHocQuery(): DcqlQuery {
  return {
    credentials: [
      {
        id: AD_HOC_QUERY_ID,
        format: 'mso_mdoc',
        meta: {},
      },
    ],
  }
}

function firstMdocQueryId(dcql: DcqlQuery): string | null {
  const query = dcql.credentials.find((credential) => credential.format === 'mso_mdoc')
  return query?.id ?? null
}
