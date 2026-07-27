/**
 * The label catalog: every user-visible string the built-in UI renders, as one typed object.
 *
 * `useVerification()` never produces copy — status and errors are stable codes, and turning
 * codes into words is a UI concern. This module is where that happens for `<AgeGate/>` and
 * `<VerificationQr/>`; integrators with their own UI read the codes directly and never pay for
 * any of this.
 *
 * Resolution is deliberately explicit — `overrides` beat the `locale` catalog, which beats
 * English — and never automatic: nothing here reads `navigator.language`, because a
 * server-rendered page would then hydrate with different text than it shipped. Pass the locale
 * the page has already negotiated.
 */

import type { EudikitErrorCode } from '@eudikit/core'
import { de } from './locales/de.js'
import { en } from './locales/en.js'
import { tr } from './locales/tr.js'
import type { VerificationStatus } from './use-verification.js'

/** The locales with a built-in catalog. Anything else resolves to English. */
export type Locale = 'en' | 'tr' | 'de'

const USER_FACING_ERROR_CODES = [
  'USER_DECLINED_OR_NO_CREDENTIAL',
  'WALLET_UNAVAILABLE',
  'WALLET_FORMAT_UNSUPPORTED',
  'WALLET_REJECTED_REQUEST',
  'UNSUPPORTED_PROTOCOL',
  'SESSION_ALREADY_CONSUMED',
  'SESSION_NOT_FOUND',
  'SESSION_EXPIRED',
  'VERIFICATION_FAILED',
] as const satisfies readonly EudikitErrorCode[]

/**
 * The curated subset of `EudikitErrorCode` that has copy of its own in every catalog. Codes
 * outside it describe configuration mistakes or internals; they render as `errors.generic`
 * while the error object keeps the real code.
 */
export type UserFacingErrorCode = (typeof USER_FACING_ERROR_CODES)[number]

/**
 * Every user-visible string of the built-in UI, `aria` labels included — nothing the widget
 * renders is written anywhere else. A full catalog also satisfies
 * `EudikitReactLabelsOverrides`, so a hand-written translation can be passed straight to the
 * `labels` prop.
 */
export interface EudikitReactLabels {
  /**
   * BCP 47 language tag written to the widget root's `lang` attribute, so assistive technology
   * switches pronunciation with the catalog.
   */
  lang: string
  /** The start button. */
  trigger: string
  /** The cancel button, shown while an attempt is running. */
  cancel: string
  /** The same-device wallet link. */
  openWallet: string
  /** The line under the QR code pointing at the wallet app on a phone. */
  scanQrHint: string
  /** Accessible name of the QR code image. */
  qrLabel: string
  /** The live status line, by verification status. An empty string renders an empty region. */
  status: Record<VerificationStatus, string>
  /** Failure copy by user-facing code, plus the mandatory `generic` line for everything else. */
  errors: Record<UserFacingErrorCode | 'generic', string>
}

/** `EudikitReactLabels` with every field optional — the shape of the `labels` prop. */
export type EudikitReactLabelsOverrides = {
  [K in keyof EudikitReactLabels]?: EudikitReactLabels[K] extends string
    ? string
    : Partial<EudikitReactLabels[K]>
}

/**
 * Resolves the catalog for a locale and applies overrides on top, field by field. Pure: same
 * inputs, same output, and the built-in catalogs are never mutated.
 */
export function getLabels(
  locale?: Locale,
  overrides?: EudikitReactLabelsOverrides
): EudikitReactLabels {
  const base = catalogFor(locale)
  return {
    lang: pick(overrides?.lang, base.lang),
    trigger: pick(overrides?.trigger, base.trigger),
    cancel: pick(overrides?.cancel, base.cancel),
    openWallet: pick(overrides?.openWallet, base.openWallet),
    scanQrHint: pick(overrides?.scanQrHint, base.scanQrHint),
    qrLabel: pick(overrides?.qrLabel, base.qrLabel),
    status: mergeSection(base.status, overrides?.status),
    errors: mergeSection(base.errors, overrides?.errors),
  }
}

/** Whether `<AgeGate/>` has dedicated copy for a code, or will show the `generic` line. */
export function isUserFacingErrorCode(code: EudikitErrorCode): code is UserFacingErrorCode {
  return USER_FACING_SET.has(code)
}

/** The failure line for a code: its own copy when it is user-facing, `generic` otherwise. */
export function getErrorText(labels: EudikitReactLabels, code: EudikitErrorCode): string {
  return isUserFacingErrorCode(code) ? labels.errors[code] : labels.errors.generic
}

const USER_FACING_SET: ReadonlySet<string> = new Set(USER_FACING_ERROR_CODES)

function catalogFor(locale: Locale | undefined): EudikitReactLabels {
  switch (locale) {
    case 'tr':
      return tr
    case 'de':
      return de
    default:
      return en
  }
}

/** The `typeof` check keeps a JavaScript caller's `null` or junk value from erasing copy. */
function pick(override: string | undefined, fallback: string): string {
  return typeof override === 'string' ? override : fallback
}

function mergeSection<K extends string>(
  base: Readonly<Record<K, string>>,
  overrides: Partial<Record<K, string>> | undefined
): Record<K, string> {
  const merged: Record<K, string> = { ...base }
  if (overrides === undefined) return merged
  for (const key of Object.keys(base) as K[]) {
    const value = overrides[key]
    if (typeof value === 'string') merged[key] = value
  }
  return merged
}
