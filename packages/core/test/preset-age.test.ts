import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { age } from '../src/presets/age.js'
import { EudikitError } from '../src/types.js'
import { crossValidate, verifiedCredential } from './support.js'

function expectError(code: string, fn: () => unknown): void {
  try {
    fn()
    expect.unreachable(`expected a ${code} EudikitError`)
  } catch (error) {
    expect(error).toBeInstanceOf(EudikitError)
    expect((error as EudikitError).code).toBe(code)
  }
}

describe('presets.age — query generation', () => {
  it('produces the default three-way alternative query, AV attestation first', () => {
    expect(age().dcql).toEqual({
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
    expect(JSON.stringify(age().dcql)).not.toContain('"values"')
  })

  it('reflects a non-default threshold in every claim path', () => {
    const query = age({ threshold: 21 }).dcql
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

  it('replaces the domestic PID defaults with the given ones', () => {
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
    expect(JSON.stringify(query)).not.toContain('pid.de')
    crossValidate(query)
  })

  it('emits only the AV attestation when domesticPids is empty', () => {
    const query = age({ domesticPids: [] }).dcql
    expect(query.credentials.map((credential) => credential.id)).toEqual(['av_proof_of_age'])
    expect(query.credential_sets).toEqual([{ options: [['av_proof_of_age']] }])
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
    const query = age({ allowBirthDateFallback: true }).dcql
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
    crossValidate(age({ allowBirthDateFallback: true, includeMdl: true }).dcql)
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
      age().extract([verifiedCredential('pid_mdoc_age', 'mso_mdoc', { age_over_18: true })])
    ).toEqual({ ageOver: true, threshold: 18, source: 'pid-mdoc' })
  })

  it('reads the nested SD-JWT age_equal_or_over structure', () => {
    expect(
      age().extract([
        verifiedCredential('pid_sdjwt_age', 'dc+sd-jwt', { age_equal_or_over: { '18': true } }),
      ])
    ).toEqual({ ageOver: true, threshold: 18, source: 'pid-sdjwt' })

    expect(
      age({ threshold: 21 }).extract([
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
    const result = age().extract([
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

  it('rejects a non-boolean age claim instead of coercing it', () => {
    expectError('PRESENTATION_MALFORMED', () =>
      age().extract([verifiedCredential('av_proof_of_age', 'mso_mdoc', { age_over_18: 'true' })])
    )
  })

  it('rejects a birth date that is not a full-date', () => {
    expectError('PRESENTATION_MALFORMED', () =>
      age({ allowBirthDateFallback: true }).extract([
        verifiedCredential('pid_mdoc_birth_date', 'mso_mdoc', { birth_date: '27.07.2008' }),
      ])
    )
  })
})
