/**
 * `@eudikit/core` — the framework-agnostic verifier engine.
 *
 * STATUS: pre-release. Implemented: the session adapters, the `age` and `country` presets
 * (DCQL generation + claim extraction), the internal SessionTranscript module
 * (`src/mdoc/session-transcript.ts`, validated against the OpenID4VP 1.0 Appendix B.2.6 test
 * vectors), request production for the unsigned and signed flows (JAR with `x5c`,
 * by-value and `request_uri` by-reference transport), both response sides — `verify` for the
 * Digital Credentials API (`dc_api` / `dc_api.jwt`) and `handleWalletResponse` for
 * `direct_post` / `direct_post.jwt` — the full mdoc verification chain (issuer signature,
 * value digests, device signature over the rebuilt SessionTranscript, DCQL post-validation),
 * the AV trusted-list layer (ETSI TS 119 612 fetch + parse + DS byte-match, stale-cache
 * honesty), result polling (`getResult`), the session-less `verifyPresentation` for
 * `mso_mdoc`, and the HTTP handlers (`@eudikit/core/handler`, `@eudikit/core/next`).
 * Still throwing through `notImplemented()`: SD-JWT VC verification.
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
