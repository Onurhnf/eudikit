/**
 * `createVerifier()` — resolves the config once and wires it to the per-call entry points.
 *
 * Live in this release: `requests.create` (unsigned flows), the QR/deep-link response side —
 * `handleWalletResponse` (direct_post), `getResult` (polling) — and the session-less
 * `verifyPresentation` for `mso_mdoc`. Still throwing through `notImplemented()`: `verify`
 * (the DC API response entry point), `handleRequestUri` (JAR by reference), and the SD-JWT VC
 * half of `verifyPresentation`.
 */

import { notImplemented } from '../internal/not-implemented.js'
import type {
  CreatedRequest,
  CreateRequestOptions,
  PresetDefinition,
  SessionStatus,
  VerificationResult,
  Verifier,
  VerifierConfig,
} from '../types.js'
import { resolveVerifierConfig } from './config.js'
import { createRequest, presetRegistryKey } from './create-request.js'
import { getResult } from './get-result.js'
import { handleWalletResponse } from './handle-wallet-response.js'
import { PresetRegistry } from './preset-registry.js'
import { type VerifyPresentationInput, verifyPresentation } from './verify-presentation.js'

export function createVerifier(config: VerifierConfig): Verifier {
  const resolved = resolveVerifierConfig(config)
  const presets = new PresetRegistry()

  return {
    requests: {
      create<TClaims>(options: CreateRequestOptions<TClaims>): Promise<CreatedRequest> {
        if (options !== null && typeof options === 'object' && options.preset !== undefined) {
          const preset = options.preset as PresetDefinition<unknown>
          presets.register(presetRegistryKey(preset), preset)
        }
        return createRequest(resolved, options)
      },
    },

    verify() {
      return notImplemented('verifier.verify() (Digital Credentials API responses)')
    },
    handleWalletResponse(request: Request): Promise<Response> {
      return handleWalletResponse(resolved, presets, request)
    },
    handleRequestUri() {
      return notImplemented('verifier.handleRequestUri() (JAR by reference)')
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
}
