/**
 * `createVerifier()` — resolves the config once and wires it to the per-call entry points.
 *
 * All five entry points are live: `requests.create` (unsigned and signed flows), `verify`
 * (DC API responses), `handleWalletResponse` (direct_post / direct_post.jwt),
 * `handleRequestUri` (JAR by reference) and `getResult` (polling), plus the session-less
 * `verifyPresentation` for `mso_mdoc`. The SD-JWT VC half of `verifyPresentation` still
 * throws through `notImplemented()`.
 */

import type {
  CreatedRequest,
  CreateRequestOptions,
  PresetDefinition,
  SessionStatus,
  VerificationResult,
  Verifier,
  VerifierConfig,
  VerifyInput,
} from '../types.js'
import { resolveVerifierConfig } from './config.js'
import { createRequest, presetRegistryKey } from './create-request.js'
import { getResult } from './get-result.js'
import { handleRequestUri } from './handle-request-uri.js'
import { handleWalletResponse } from './handle-wallet-response.js'
import { PresetRegistry } from './preset-registry.js'
import { verifyDcApiResponse } from './verify.js'
import { type VerifyPresentationInput, verifyPresentation } from './verify-presentation.js'

/**
 * Bridge between a `Verifier` and the HTTP handler subpath: the handler needs the resolved
 * `routeBasePath` to mount its routes, and the public `Verifier` interface deliberately
 * exposes no configuration. `Symbol.for` keeps the link working even if module duplication
 * ever produces two copies of this file.
 */
export const VERIFIER_INTERNAL = Symbol.for('eudikit.core.verifier-internal.v1')

export interface VerifierInternal {
  routeBasePath: string
}

export function verifierInternal(verifier: Verifier): VerifierInternal | null {
  const internal = (verifier as unknown as Record<symbol, unknown>)[VERIFIER_INTERNAL]
  if (typeof internal !== 'object' || internal === null) return null
  return internal as VerifierInternal
}

export function createVerifier(config: VerifierConfig): Verifier {
  const resolved = resolveVerifierConfig(config)
  const presets = new PresetRegistry()

  const verifier: Verifier = {
    requests: {
      create<TClaims>(options: CreateRequestOptions<TClaims>): Promise<CreatedRequest> {
        if (options !== null && typeof options === 'object' && options.preset !== undefined) {
          const preset = options.preset as PresetDefinition<unknown>
          presets.register(presetRegistryKey(preset), preset)
        }
        return createRequest(resolved, options)
      },
    },

    verify<TClaims>(input: VerifyInput): Promise<VerificationResult<TClaims>> {
      return verifyDcApiResponse(resolved, presets, input) as Promise<VerificationResult<TClaims>>
    },
    handleWalletResponse(request: Request): Promise<Response> {
      return handleWalletResponse(resolved, presets, request)
    },
    handleRequestUri(request: Request, sessionId: string): Promise<Response> {
      return handleRequestUri(resolved, request, sessionId)
    },
    getResult<TClaims>(
      sessionId: string,
      options?: { responseCode?: string }
    ): Promise<SessionStatus<TClaims>> {
      return getResult(resolved, sessionId, options) as Promise<SessionStatus<TClaims>>
    },
    verifyPresentation(input: VerifyPresentationInput): Promise<VerificationResult> {
      return verifyPresentation(resolved, input)
    },
  }

  const internal: VerifierInternal = { routeBasePath: resolved.routeBasePath }
  Object.defineProperty(verifier, VERIFIER_INTERNAL, { value: internal, enumerable: false })
  return verifier
}
