'use client'

/**
 * `@eudikit/react` — transport and UI only.
 *
 * This package never verifies anything. It calls the Digital Credentials API, falls back to a QR
 * code, polls for a result, and renders. Every cryptographic decision happens on the server, in
 * `@eudikit/core`: verification in the client would be no verification at all.
 *
 * That separation is enforced, not just documented: nothing here imports `@eudikit/core` at
 * runtime — only its types — so no verifier code, key material or server dependency can be
 * pulled into a browser bundle by accident.
 *
 * The entry point carries `'use client'` because everything it exports is browser code: a React
 * Server Component can import `<AgeGate/>` and render it without a wrapper. Server *rendering*
 * still works — importing this module touches neither `window` nor `document`, and every browser
 * API is reached from an event handler or an effect.
 *
 * The label catalogs (plain data, usable in server components) live at `@eudikit/react/locales`.
 */

export {
  AgeGate,
  type AgeGateDecision,
  type AgeGateProps,
  type AgeGateRenderState,
} from './age-gate.js'
export { DC_API_PROTOCOLS, digitalCredentialsAvailable } from './dc-api.js'
export {
  type EudikitReactLabels,
  type EudikitReactLabelsOverrides,
  getErrorText,
  getLabels,
  isUserFacingErrorCode,
  type Locale,
  type UserFacingErrorCode,
} from './labels.js'
export {
  QrCode,
  type QrCodeProps,
  VerificationQr,
  type VerificationQrProps,
} from './qr-code.js'
export {
  type UseVerificationOptions,
  type UseVerificationResult,
  useVerification,
  type VerificationError,
  type VerificationStatus,
} from './use-verification.js'
