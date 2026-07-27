/**
 * `@eudikit/core` — the framework-agnostic verifier engine.
 *
 * STATUS: pre-release. Implemented so far: the session adapters, the `age` and `country`
 * presets (DCQL generation + claim extraction), the internal SessionTranscript module
 * (`src/mdoc/session-transcript.ts`, validated against the OpenID4VP 1.0 Appendix B.2.6 test
 * vectors), the request-production half of the verifier — `createVerifier` config resolution
 * plus `requests.create` for the unsigned flows — and the QR/deep-link response side: the
 * `direct_post` endpoint (`handleWalletResponse`), the full mdoc verification chain
 * (issuer signature, value digests, device signature over the rebuilt SessionTranscript,
 * DS-direct-match trust, DCQL post-validation), result polling (`getResult`) and the
 * session-less `verifyPresentation` for `mso_mdoc`. Still throwing through
 * `notImplemented()`: signed request objects (JAR), `request_uri` transport, the DC API
 * response entry point (`verify`), SD-JWT VC verification and trusted-list fetching.
 */

import { notImplemented } from './internal/not-implemented.js'
import { age } from './presets/age.js'
import { country } from './presets/country.js'
import type { PresetDefinition } from './types.js'

// ---------------------------------------------------------------------------
// The verifier
// ---------------------------------------------------------------------------

export { createVerifier } from './verifier/create-verifier.js'

// ---------------------------------------------------------------------------
// Presets
// ---------------------------------------------------------------------------

/**
 * Defines a custom preset. This is the one entry point that is genuinely complete: it is a
 * type-level helper that returns its argument unchanged.
 */
export function definePreset<TClaims>(def: PresetDefinition<TClaims>): PresetDefinition<TClaims> {
  return def
}

/**
 * `presets.identity` — @alpha NAME RESERVATION. Holds a place on the API surface for the KYC /
 * eIDAS Art 5f wave (December 2027). Calling it in v1 always throws; the type signature will be
 * defined in a later version.
 */
function identity(_options?: never): PresetDefinition<never> {
  return notImplemented('presets.identity() (reserved for a later version)')
}

export const presets = { age, country, identity } as const

// ---------------------------------------------------------------------------
// Session adapters
// ---------------------------------------------------------------------------

export { kvSessionAdapter } from './session/kv.js'
export { memorySessionAdapter } from './session/memory.js'
export { redisSessionAdapter } from './session/redis.js'

// ---------------------------------------------------------------------------
// Public types + the error class
// ---------------------------------------------------------------------------

export type {
  AgeClaims,
  AgeOptions,
  CertificateInput,
  Channel,
  Check,
  CheckId,
  ClientIdPrefix,
  CountryClaims,
  CountryOptions,
  CreatedRequest,
  CreateRequestOptions,
  CredentialFormat,
  DcqlCredentialQuery,
  DcqlQuery,
  EudikitErrorCategory,
  EudikitErrorCode,
  Jwk,
  KvLikeClient,
  PresetDefinition,
  ProtocolAdapter,
  RedisLikeClient,
  SessionAdapter,
  SessionStatus,
  StoredRecord,
  TrustCacheAdapter,
  TrustConfig,
  VerificationResult,
  VerifiedCredential,
  Verifier,
  VerifierConfig,
  VerifierKeys,
  VerifyInput,
  WalletProfile,
} from './types.js'
export { EudikitError } from './types.js'
