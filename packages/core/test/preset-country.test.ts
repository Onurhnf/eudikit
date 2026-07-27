import { describe, expect, it } from 'vitest'
import { country } from '../src/presets/country.js'
import type { CountryOptions } from '../src/types.js'
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

describe('presets.country — query generation', () => {
  it('asks for nationalities when attribute is nationality', () => {
    expect(country({ attribute: 'nationality' }).dcql).toEqual({
      credentials: [
        {
          id: 'pid_sdjwt_country',
          format: 'dc+sd-jwt',
          meta: { vct_values: ['urn:eudi:pid:1'] },
          claims: [{ path: ['nationalities', null] }],
        },
        {
          id: 'pid_mdoc_country',
          format: 'mso_mdoc',
          meta: { doctype_value: 'eu.europa.ec.eudi.pid.1' },
          claims: [{ path: ['eu.europa.ec.eudi.pid.1', 'nationality'], intent_to_retain: false }],
        },
      ],
      credential_sets: [{ options: [['pid_sdjwt_country'], ['pid_mdoc_country']] }],
    })
  })

  it('asks for the residence country when attribute is residence', () => {
    const query = country({ attribute: 'residence' }).dcql
    expect(query.credentials[0]?.claims?.[0]?.path).toEqual(['address', 'country'])
    expect(query.credentials[1]?.claims?.[0]?.path).toEqual([
      'eu.europa.ec.eudi.pid.1',
      'resident_country',
    ])
  })

  it('both variants pass the dcql package', () => {
    crossValidate(country({ attribute: 'nationality' }).dcql)
    crossValidate(country({ attribute: 'residence' }).dcql)
  })

  it('refuses to run without an explicit attribute', () => {
    expectError('CONFIG_INVALID', () => country({} as CountryOptions))
    expectError('CONFIG_INVALID', () => country({ attribute: 'citizenship' as never }))
  })
})

describe('presets.country — extract', () => {
  it('keeps the mdoc nationality array as a set', () => {
    const result = country({ attribute: 'nationality' }).extract([
      verifiedCredential('pid_mdoc_country', 'mso_mdoc', { nationality: ['DE', 'TR'] }),
    ])
    expect(result).toEqual({ attribute: 'nationality', countries: ['DE', 'TR'] })
  })

  it('wraps a single value into a one-element set', () => {
    expect(
      country({ attribute: 'nationality' }).extract([
        verifiedCredential('pid_mdoc_country', 'mso_mdoc', { nationality: 'DE' }),
      ]).countries
    ).toEqual(['DE'])
  })

  it('reads SD-JWT nationalities and de-duplicates them', () => {
    expect(
      country({ attribute: 'nationality' }).extract([
        verifiedCredential('pid_sdjwt_country', 'dc+sd-jwt', { nationalities: ['DE', 'DE', 'TR'] }),
      ]).countries
    ).toEqual(['DE', 'TR'])
  })

  it('reads the nested SD-JWT address.country for residence', () => {
    expect(
      country({ attribute: 'residence' }).extract([
        verifiedCredential('pid_sdjwt_country', 'dc+sd-jwt', { address: { country: 'DE' } }),
      ])
    ).toEqual({ attribute: 'residence', countries: ['DE'] })
  })

  it('reads the mdoc resident_country for residence', () => {
    expect(
      country({ attribute: 'residence' }).extract([
        verifiedCredential('pid_mdoc_country', 'mso_mdoc', { resident_country: 'FI' }),
      ]).countries
    ).toEqual(['FI'])
  })

  it('passes the reserved QU and QS codes through unchanged', () => {
    expect(
      country({ attribute: 'nationality' }).extract([
        verifiedCredential('pid_mdoc_country', 'mso_mdoc', { nationality: ['QU', 'QS'] }),
      ]).countries
    ).toEqual(['QU', 'QS'])
  })

  it('prefers the SD-JWT credential when both are present', () => {
    expect(
      country({ attribute: 'nationality' }).extract([
        verifiedCredential('pid_mdoc_country', 'mso_mdoc', { nationality: ['FR'] }),
        verifiedCredential('pid_sdjwt_country', 'dc+sd-jwt', { nationalities: ['DE'] }),
      ]).countries
    ).toEqual(['DE'])
  })

  it('rejects a presentation with no matching credential', () => {
    expectError('PRESENTATION_MALFORMED', () =>
      country({ attribute: 'nationality' }).extract([
        verifiedCredential('something_else', 'mso_mdoc', { nationality: ['DE'] }),
      ])
    )
  })

  it('rejects a matching credential that is missing the claim', () => {
    expectError('PRESENTATION_MALFORMED', () =>
      country({ attribute: 'residence' }).extract([
        verifiedCredential('pid_sdjwt_country', 'dc+sd-jwt', { address: {} }),
      ])
    )
  })

  it('rejects non-string entries instead of coercing them', () => {
    expectError('PRESENTATION_MALFORMED', () =>
      country({ attribute: 'nationality' }).extract([
        verifiedCredential('pid_mdoc_country', 'mso_mdoc', { nationality: [276] }),
      ])
    )
  })
})
