import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { age } from '../src/presets/age.js'
import type { CredentialFormat } from '../src/types.js'
import { EudikitError } from '../src/types.js'
import { crossValidate, verifiedCredential } from './support.js'

function expectError(code: string, fn: () => unknown): EudikitError {
  try {
    fn()
  } catch (error) {
    expect(error).toBeInstanceOf(EudikitError)
    expect((error as EudikitError).code).toBe(code)
    return error as EudikitError
  }
  expect.unreachable(`expected a ${code} EudikitError`)
}

const GERMAN_PIDS: Array<{ format: CredentialFormat; id: string }> = [
  { format: 'mso_mdoc', id: 'eu.europa.ec.eudi.pid.de.1' },
  { format: 'dc+sd-jwt', id: 'urn:eudi:pid:de:1' },
]

describe('presets.age — query generation', () => {
  it('produces an AV-attestation-only query by default', () => {
    expect(age().dcql).toEqual({
      credentials: [
        {
          id: 'av_proof_of_age',
          format: 'mso_mdoc',
          meta: { doctype_value: 'eu.europa.ec.av.1' },
          claims: [{ path: ['eu.europa.ec.av.1', 'age_over_18'], intent_to_retain: false }],
        },
      ],
      credential_sets: [{ options: [['av_proof_of_age']] }],
    })
  })

  it('keeps every non-mdoc format out of the default query', () => {
    // A wallet that does not support a queried format rejects the whole request instead of
    // skipping that alternative, so the default must never mention dc+sd-jwt.
    expect(JSON.stringify(age().dcql)).not.toContain('sd-jwt')
  })

  it('treats an explicitly empty domesticPids the same as the default', () => {
    expect(age({ domesticPids: [] }).dcql).toEqual(age().dcql)
  })

  it('expands to the three-way alternative query when domestic PIDs are given', () => {
    expect(age({ domesticPids: GERMAN_PIDS }).dcql).toEqual({
      credentials: [
        {
          id: 'av_proof_of_age',
          format: 'mso_mdoc',
          meta: { doctype_value: 'eu.europa.ec.av.1' },
          claims: [{ path: ['eu.europa.ec.av.1', 'age_over_18'], intent_to_retain: false }],
        },
        {
          id: 'pid_mdoc_age',
          format: 'mso_mdoc',
          meta: { doctype_value: 'eu.europa.ec.eudi.pid.de.1' },
          claims: [
            { path: ['eu.europa.ec.eudi.pid.de.1', 'age_over_18'], intent_to_retain: false },
          ],
        },
        {
          id: 'pid_sdjwt_age',
          format: 'dc+sd-jwt',
          meta: { vct_values: ['urn:eudi:pid:1', 'urn:eudi:pid:de:1'] },
          claims: [{ path: ['age_equal_or_over', '18'] }],
        },
      ],
      credential_sets: [{ options: [['av_proof_of_age'], ['pid_mdoc_age'], ['pid_sdjwt_age']] }],
    })
  })

  it('never asks the wallet to value-match the boolean', () => {
    expect(JSON.stringify(age({ domesticPids: GERMAN_PIDS }).dcql)).not.toContain('"values"')
  })

  it('reflects a non-default threshold in every claim path', () => {
    const query = age({ threshold: 21, domesticPids: GERMAN_PIDS }).dcql
    const serialized = JSON.stringify(query)
    expect(serialized).toContain('age_over_21')
    expect(serialized).toContain('"age_equal_or_over","21"')
    expect(serialized).not.toContain('age_over_18')
  })

  it('rejects a threshold that is not a positive integer', () => {
    expectError('CONFIG_INVALID', () => age({ threshold: 17.5 }))
    expectError('CONFIG_INVALID', () => age({ threshold: 0 }))
    expectError('CONFIG_INVALID', () => age({ threshold: -18 }))
  })

  it('accepts several domestic PIDs and merges the vct list', () => {
    const query = age({
      domesticPids: [
        { format: 'mso_mdoc', id: 'eu.europa.ec.eudi.pid.fr.1' },
        { format: 'mso_mdoc', id: 'eu.europa.ec.eudi.pid.it.1' },
        { format: 'dc+sd-jwt', id: 'urn:eudi:pid:fr:1' },
      ],
    }).dcql

    expect(query.credentials.map((credential) => credential.id)).toEqual([
      'av_proof_of_age',
      'pid_mdoc_age',
      'pid_mdoc_age_2',
      'pid_sdjwt_age',
    ])
    expect(query.credentials[1]?.meta.doctype_value).toBe('eu.europa.ec.eudi.pid.fr.1')
    expect(query.credentials[2]?.meta.doctype_value).toBe('eu.europa.ec.eudi.pid.it.1')
    expect(query.credentials[3]?.meta.vct_values).toEqual(['urn:eudi:pid:1', 'urn:eudi:pid:fr:1'])
    crossValidate(query)
  })

  it('rejects a domestic PID with an unknown format', () => {
    expectError('CONFIG_INVALID', () =>
      age({ domesticPids: [{ format: 'ldp_vc' as never, id: 'x' }] })
    )
  })

  it('keeps birth_date out of the query unless the fallback is enabled', () => {
    expect(JSON.stringify(age().dcql)).not.toMatch(/birth/)
  })

  it('adds the birth-date options last when the fallback is enabled', () => {
    const query = age({ allowBirthDateFallback: true, domesticPids: GERMAN_PIDS }).dcql
    expect(query.credential_sets?.[0]?.options).toEqual([
      ['av_proof_of_age'],
      ['pid_mdoc_age'],
      ['pid_sdjwt_age'],
      ['pid_mdoc_birth_date'],
      ['pid_sdjwt_birth_date'],
    ])

    const mdocBirthDate = query.credentials.find((c) => c.id === 'pid_mdoc_birth_date')
    expect(mdocBirthDate?.meta.doctype_value).toBe('eu.europa.ec.eudi.pid.1')
    expect(mdocBirthDate?.claims?.[0]?.path).toEqual(['eu.europa.ec.eudi.pid.1', 'birth_date'])

    const sdJwtBirthDate = query.credentials.find((c) => c.id === 'pid_sdjwt_birth_date')
    expect(sdJwtBirthDate?.claims?.[0]?.path).toEqual(['birthdate'])
    crossValidate(query)
  })

  it('adds an mDL option when includeMdl is set', () => {
    const query = age({ includeMdl: true }).dcql
    const mdl = query.credentials.find((credential) => credential.id === 'mdl_age')
    expect(mdl?.meta.doctype_value).toBe('org.iso.18013.5.1.mDL')
    expect(mdl?.claims?.[0]?.path).toEqual(['org.iso.18013.5.1', 'age_over_18'])
    crossValidate(query)
  })

  it('every generated variant passes the dcql package', () => {
    crossValidate(age().dcql)
    crossValidate(age({ threshold: 65 }).dcql)
    crossValidate(age({ domesticPids: GERMAN_PIDS }).dcql)
    crossValidate(age({ allowBirthDateFallback: true, includeMdl: true }).dcql)
  })

  it('declares the expected claim types for the DCQL post-validation', () => {
    expect(age().claimTypes).toEqual({
      av_proof_of_age: { age_over_18: { type: 'boolean' } },
    })
    expect(
      age({ threshold: 21, domesticPids: GERMAN_PIDS, allowBirthDateFallback: true }).claimTypes
    ).toEqual({
      av_proof_of_age: { age_over_21: { type: 'boolean' } },
      pid_mdoc_age: { age_over_21: { type: 'boolean' } },
      pid_mdoc_birth_date: { birth_date: { type: 'string', redactValue: true } },
    })
  })
})

describe('presets.age — extract', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-07-27T12:00:00Z'))
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('reads the AV attestation boolean server-side', () => {
    const preset = age()
    expect(
      preset.extract([verifiedCredential('av_proof_of_age', 'mso_mdoc', { age_over_18: true })])
    ).toEqual({ ageOver: true, threshold: 18, source: 'av-attestation' })

    expect(
      preset.extract([verifiedCredential('av_proof_of_age', 'mso_mdoc', { age_over_18: false })])
    ).toEqual({ ageOver: false, threshold: 18, source: 'av-attestation' })
  })

  it('reads a domestic PID mdoc age claim', () => {
    expect(
      age({ domesticPids: GERMAN_PIDS }).extract([
        verifiedCredential('pid_mdoc_age', 'mso_mdoc', { age_over_18: true }),
      ])
    ).toEqual({ ageOver: true, threshold: 18, source: 'pid-mdoc' })
  })

  it('reads the nested SD-JWT age_equal_or_over structure', () => {
    expect(
      age({ domesticPids: GERMAN_PIDS }).extract([
        verifiedCredential('pid_sdjwt_age', 'dc+sd-jwt', { age_equal_or_over: { '18': true } }),
      ])
    ).toEqual({ ageOver: true, threshold: 18, source: 'pid-sdjwt' })

    expect(
      age({ threshold: 21, domesticPids: GERMAN_PIDS }).extract([
        verifiedCredential('pid_sdjwt_age', 'dc+sd-jwt', { age_equal_or_over: { '21': false } }),
      ])
    ).toEqual({ ageOver: false, threshold: 21, source: 'pid-sdjwt' })
  })

  it('reports an mDL answer as its own source', () => {
    expect(
      age({ includeMdl: true }).extract([
        verifiedCredential('mdl_age', 'mso_mdoc', { age_over_18: true }),
      ])
    ).toEqual({ ageOver: true, threshold: 18, source: 'mdl' })
  })

  it('computes the age from an mdoc birth date server-side', () => {
    const preset = age({ allowBirthDateFallback: true })

    // 18th birthday is exactly today (system time 2026-07-27).
    expect(
      preset.extract([
        verifiedCredential('pid_mdoc_birth_date', 'mso_mdoc', { birth_date: '2008-07-27' }),
      ])
    ).toEqual({ ageOver: true, threshold: 18, source: 'birth-date' })

    // 18th birthday is tomorrow.
    expect(
      preset.extract([
        verifiedCredential('pid_mdoc_birth_date', 'mso_mdoc', { birth_date: '2008-07-28' }),
      ])
    ).toEqual({ ageOver: false, threshold: 18, source: 'birth-date' })
  })

  it('computes the age from an SD-JWT birthdate claim', () => {
    expect(
      age({ allowBirthDateFallback: true }).extract([
        verifiedCredential('pid_sdjwt_birth_date', 'dc+sd-jwt', { birthdate: '1990-01-15' }),
      ])
    ).toEqual({ ageOver: true, threshold: 18, source: 'birth-date' })
  })

  it('treats a February 29 birthday as reached on March 1 of non-leap years', () => {
    const preset = age({ allowBirthDateFallback: true })
    const born = [
      verifiedCredential('pid_mdoc_birth_date', 'mso_mdoc', { birth_date: '2008-02-29' }),
    ]

    vi.setSystemTime(new Date('2026-02-28T12:00:00Z'))
    expect(preset.extract(born).ageOver).toBe(false)
    vi.setSystemTime(new Date('2026-03-01T12:00:00Z'))
    expect(preset.extract(born).ageOver).toBe(true)
  })

  it('never leaks the raw birth date into the claims', () => {
    const result = age({ allowBirthDateFallback: true }).extract([
      verifiedCredential('pid_mdoc_birth_date', 'mso_mdoc', { birth_date: '2008-07-27' }),
    ])
    expect(JSON.stringify(result)).not.toContain('2008')
    expect(Object.keys(result)).toEqual(['ageOver', 'threshold', 'source'])
  })

  it('prefers the AV attestation when several credentials are present', () => {
    const result = age({ domesticPids: GERMAN_PIDS }).extract([
      verifiedCredential('pid_mdoc_age', 'mso_mdoc', { age_over_18: false }),
      verifiedCredential('av_proof_of_age', 'mso_mdoc', { age_over_18: true }),
    ])
    expect(result).toEqual({ ageOver: true, threshold: 18, source: 'av-attestation' })
  })

  it('rejects a presentation with no matching credential', () => {
    expectError('PRESENTATION_MALFORMED', () =>
      age().extract([verifiedCredential('something_else', 'mso_mdoc', { age_over_18: true })])
    )
  })

  it('rejects a birth date that is not a full-date, without repeating the value', () => {
    const error = expectError('PRESENTATION_MALFORMED', () =>
      age({ allowBirthDateFallback: true }).extract([
        verifiedCredential('pid_mdoc_birth_date', 'mso_mdoc', { birth_date: '27.07.2008' }),
      ])
    )
    expect(error.message).not.toContain('2008')
  })
})

describe('presets.age — extract error messages', () => {
  it('reports the received type and value for a mistyped age claim', () => {
    const error = expectError('PRESENTATION_MALFORMED', () =>
      age().extract([verifiedCredential('av_proof_of_age', 'mso_mdoc', { age_over_18: 'false' })])
    )
    expect(error.message).toBe(
      'expected a boolean "age_over_18" claim, received a string ("false") — the credential ' +
        'was issued with a value of the wrong type'
    )
  })

  it('shows number values verbatim', () => {
    const error = expectError('PRESENTATION_MALFORMED', () =>
      age().extract([verifiedCredential('av_proof_of_age', 'mso_mdoc', { age_over_18: 1 })])
    )
    expect(error.message).toBe(
      'expected a boolean "age_over_18" claim, received a number (1) — the credential ' +
        'was issued with a value of the wrong type'
    )
  })

  it('names only the type for object values', () => {
    const error = expectError('PRESENTATION_MALFORMED', () =>
      age().extract([
        verifiedCredential('av_proof_of_age', 'mso_mdoc', { age_over_18: { nested: true } }),
      ])
    )
    expect(error.message).toBe(
      'expected a boolean "age_over_18" claim, received an object — the credential ' +
        'was issued with a value of the wrong type'
    )
  })

  it('reports a missing claim as received undefined, without the issuance clause', () => {
    const error = expectError('PRESENTATION_MALFORMED', () =>
      age().extract([verifiedCredential('av_proof_of_age', 'mso_mdoc', {})])
    )
    expect(error.message).toBe('expected a boolean "age_over_18" claim, received undefined')
  })

  it('keeps long or control-character string values out of the message', () => {
    const long = 'x'.repeat(40)
    const longError = expectError('PRESENTATION_MALFORMED', () =>
      age().extract([verifiedCredential('av_proof_of_age', 'mso_mdoc', { age_over_18: long })])
    )
    expect(longError.message).toContain('received a string —')
    expect(longError.message).not.toContain(long)

    const sneakyError = expectError('PRESENTATION_MALFORMED', () =>
      age().extract([
        verifiedCredential('av_proof_of_age', 'mso_mdoc', { age_over_18: 'a\u0000b' }),
      ])
    )
    expect(sneakyError.message).toContain('received a string —')
    expect(sneakyError.message).not.toContain('a\u0000b')
  })

  it('never places a birth date value in the message, only its type', () => {
    const error = expectError('PRESENTATION_MALFORMED', () =>
      age({ allowBirthDateFallback: true }).extract([
        verifiedCredential('pid_mdoc_birth_date', 'mso_mdoc', { birth_date: 19900115 }),
      ])
    )
    expect(error.message).toBe(
      'expected a string "birth_date" claim, received a number — the credential ' +
        'was issued with a value of the wrong type'
    )
    expect(error.message).not.toContain('19900115')
  })
})
