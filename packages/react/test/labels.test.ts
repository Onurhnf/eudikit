/**
 * The label mechanism: pure resolution (`overrides` > `locale` > English), catalog completeness
 * across every shipped locale, and the curated error mapping the widget renders from.
 */

import type { EudikitErrorCode } from '@eudikit/core'
import { describe, expect, it } from 'vitest'
import {
  type EudikitReactLabels,
  type EudikitReactLabelsOverrides,
  getErrorText,
  getLabels,
  isUserFacingErrorCode,
  type Locale,
} from '../src/labels.js'
import { de, en, tr } from '../src/locales/index.js'

describe('getLabels', () => {
  it('resolves the English catalog by default', () => {
    expect(getLabels()).toEqual(en)
    expect(getLabels('en')).toEqual(en)
  })

  it('resolves a locale catalog', () => {
    expect(getLabels('tr')).toEqual(tr)
    expect(getLabels('de')).toEqual(de)
  })

  it('falls back to English for a locale it does not know', () => {
    expect(getLabels('fr' as Locale)).toEqual(en)
  })

  it('lets overrides beat the locale catalog field by field', () => {
    const labels = getLabels('tr', { trigger: 'Kanıtla', errors: { generic: 'Olmadı.' } })
    expect(labels.trigger).toBe('Kanıtla')
    expect(labels.errors.generic).toBe('Olmadı.')
    expect(labels.cancel).toBe(tr.cancel)
    expect(labels.errors.WALLET_UNAVAILABLE).toBe(tr.errors.WALLET_UNAVAILABLE)
    expect(labels.status).toEqual(tr.status)
  })

  it('accepts a full catalog as overrides, so hand-written translations plug straight in', () => {
    expect(getLabels('en', de)).toEqual(de)
  })

  it('ignores undefined and non-string override values from untyped callers', () => {
    const overrides = {
      trigger: undefined,
      cancel: 42,
      status: { creating: undefined },
      errors: { generic: null },
    } as unknown as EudikitReactLabelsOverrides
    expect(getLabels('en', overrides)).toEqual(en)
  })

  it('never hands out or mutates the catalog objects themselves', () => {
    const resolved = getLabels('en', { trigger: 'Changed' })
    expect(resolved.trigger).toBe('Changed')
    expect(en.trigger).toBe('Verify your age with your wallet')
    expect(resolved).not.toBe(en)
    expect(getLabels()).not.toBe(en)
    expect(getLabels().status).not.toBe(en.status)
  })
})

describe('catalogs', () => {
  const catalogs: ReadonlyArray<[Locale, EudikitReactLabels]> = [
    ['en', en],
    ['tr', tr],
    ['de', de],
  ]

  it('are complete in every locale, aria labels included', () => {
    for (const [name, catalog] of catalogs) {
      expect(catalog.lang).toBe(name)
      expect(Object.keys(catalog.status).sort()).toEqual(Object.keys(en.status).sort())
      expect(Object.keys(catalog.errors).sort()).toEqual(Object.keys(en.errors).sort())
      const flat = [
        catalog.trigger,
        catalog.cancel,
        catalog.openWallet,
        catalog.scanQrHint,
        catalog.qrLabel,
      ]
      for (const text of flat) {
        expect(text.trim()).not.toBe('')
      }
      for (const [status, text] of Object.entries(catalog.status)) {
        // idle announces nothing and failures speak through the alert region instead.
        if (status === 'idle' || status === 'failed') expect(text).toBe('')
        else expect(text.trim()).not.toBe('')
      }
      for (const text of Object.values(catalog.errors)) {
        expect(text.trim()).not.toBe('')
      }
    }
  })
})

describe('error curation', () => {
  it('maps user-facing codes to their own line and everything else to generic', () => {
    expect(isUserFacingErrorCode('USER_DECLINED_OR_NO_CREDENTIAL')).toBe(true)
    expect(isUserFacingErrorCode('CONFIG_INVALID')).toBe(false)
    expect(isUserFacingErrorCode('INTERNAL')).toBe(false)

    expect(getErrorText(en, 'WALLET_UNAVAILABLE')).toBe(en.errors.WALLET_UNAVAILABLE)
    expect(getErrorText(tr, 'SESSION_EXPIRED')).toBe(tr.errors.SESSION_EXPIRED)

    const nonFacing: EudikitErrorCode[] = [
      'CONFIG_INVALID',
      'CONFIG_PUBLIC_BASE_URL_REQUIRED',
      'CHANNEL_PROFILE_MISMATCH',
      'TRUSTED_LIST_UNAVAILABLE',
      'INTERNAL',
    ]
    for (const code of nonFacing) {
      expect(getErrorText(en, code)).toBe(en.errors.generic)
    }
  })
})
