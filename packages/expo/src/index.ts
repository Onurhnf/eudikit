/**
 * `@eudikit/expo` — React Native / Expo transport.
 *
 * Like `@eudikit/react`, this is transport only: it moves an opaque request to the wallet and the
 * wallet's opaque response to your server. It never verifies.
 *
 * **v1 scope: deep link + QR only.** The native Android
 * Credential Manager path needs `org-iso-mdoc` (ISO 18013-7 Annex C + HPKE), which is a v1.1
 * item shipping alongside `@eudikit/iso-18013-7`. Until then `getCapabilities()` honestly reports
 * `nativeRequest: false` with `reason: 'NATIVE_PATH_V1_1'` — the surface is reserved, the
 * behaviour is not pretended.
 *
 * STATUS: skeleton — every export throws.
 */

import type { EudikitErrorCode } from '@eudikit/core'
import { EudikitError } from '@eudikit/core'

function notImplemented(surface: string): never {
  throw new EudikitError(
    'INTERNAL',
    `${surface} is not implemented yet — @eudikit/expo is a pre-release skeleton.`
  )
}

export interface Capabilities {
  platform: 'android' | 'ios'
  /** Whether the native Credential Manager path is usable. Always `false` in v1. */
  nativeRequest: boolean
  protocols: string[]
  reason?: 'IOS_NO_NATIVE_API' | 'API_LEVEL_TOO_LOW' | 'NO_PLAY_SERVICES' | 'NATIVE_PATH_V1_1'
}

/** Capability discovery — ask before choosing a strategy. */
export function getCapabilities(): Promise<Capabilities> {
  return notImplemented('getCapabilities()')
}

/**
 * Thin pass-through. `requestJson` comes from the server and is handed to the wallet **unchanged**;
 * the response is carried back to the server **unchanged**. Anything this layer rewrites is
 * something an attacker could rewrite too.
 */
export function requestCredential(_input: { requestJson: string }): Promise<{
  protocol: string
  /** Raw; carried to the server as-is for verification. */
  data: string
}> {
  return notImplemented('requestCredential()')
}

/**
 * Produces the value to put into the server's `expectedOrigins`:
 * `android:apk-key-hash:<base64url-nopad-sha256>`.
 *
 * Debug and release builds are signed differently and therefore yield **different** values — list
 * both. Getting this wrong is the number one cause of silent rejection, which is exactly why it
 * gets a helper instead of a paragraph in the docs.
 */
export function getAppOrigin(): Promise<string> {
  return notImplemented('getAppOrigin()')
}

export interface VerifyOptions {
  /** Full URL of the mounted core handler, e.g. `'https://shop.example/api/eudikit'`. */
  endpoint: string
  /** Name of a request registered in the handler, e.g. `'age'`. */
  request: string
  /** Default `'auto'`, which in v1 resolves to: deep link → (no wallet) → QR. */
  strategy?: 'auto' | 'native' | 'deep-link' | 'qr'
}

export type VerifyOutcome =
  | { status: 'verified'; claims: Record<string, unknown> }
  /**
   * On the native path, Android's `GetCredentialCancellationException` is a genuine
   * user-cancelled signal, so this layer can report it separately. The core taxonomy makes no
   * such promise on the web, where the three `access_denied` cases are indistinguishable.
   */
  | { status: 'canceled' }
  | { status: 'failed'; error: { code: EudikitErrorCode } }

/** High-level wrapper that talks to the core handler. */
export function verify(_options: VerifyOptions): Promise<VerifyOutcome> {
  return notImplemented('verify()')
}
