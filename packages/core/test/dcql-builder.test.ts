import { describe, expect, it } from 'vitest'
import { buildDcqlQuery, mdocCredentialQuery, sdJwtCredentialQuery } from '../src/dcql/build.js'
import { EudikitError } from '../src/types.js'
import { crossValidate } from './support.js'

function expectConfigInvalid(fn: () => unknown): void {
  try {
    fn()
    expect.unreachable('expected a CONFIG_INVALID EudikitError')
  } catch (error) {
    expect(error).toBeInstanceOf(EudikitError)
    expect((error as EudikitError).code).toBe('CONFIG_INVALID')
  }
}

const AV_QUERY = mdocCredentialQuery({
  id: 'av_proof_of_age',
  doctype: 'eu.europa.ec.av.1',
  claims: [{ path: ['eu.europa.ec.av.1', 'age_over_18'] }],
})

const PID_QUERY = sdJwtCredentialQuery({
  id: 'pid_sdjwt',
  vctValues: ['urn:eudi:pid:1'],
  claims: [{ path: ['nationalities', null] }],
})

describe('mdocCredentialQuery', () => {
  it('emits intent_to_retain: false unless asked otherwise', () => {
    expect(AV_QUERY.claims?.[0]?.intent_to_retain).toBe(false)

    const retaining = mdocCredentialQuery({
      id: 'q',
      doctype: 'd',
      claims: [{ path: ['d', 'given_name'], intentToRetain: true }],
    })
    expect(retaining.claims?.[0]?.intent_to_retain).toBe(true)
  })

  it('includes claim ids only when given', () => {
    const query = mdocCredentialQuery({
      id: 'q',
      doctype: 'd',
      claims: [{ id: 'a', path: ['d', 'x'] }, { path: ['d', 'y'] }],
    })
    expect(query.claims?.[0]?.id).toBe('a')
    expect(query.claims?.[1]).not.toHaveProperty('id')
  })
})

describe('sdJwtCredentialQuery', () => {
  it('rejects empty vct_values', () => {
    expectConfigInvalid(() => sdJwtCredentialQuery({ id: 'q', vctValues: [], claims: [] }))
  })
})

describe('buildDcqlQuery', () => {
  it('assembles a query the dcql package accepts', () => {
    const query = buildDcqlQuery(
      [AV_QUERY, PID_QUERY],
      [{ options: [['av_proof_of_age'], ['pid_sdjwt']] }]
    )
    crossValidate(query)
    expect(query.credentials).toHaveLength(2)
  })

  it('omits credential_sets when none are given', () => {
    const query = buildDcqlQuery([AV_QUERY])
    expect(query).not.toHaveProperty('credential_sets')
    crossValidate(query)
  })

  it('rejects an empty credentials array', () => {
    expectConfigInvalid(() => buildDcqlQuery([]))
  })

  it('rejects malformed credential ids', () => {
    expectConfigInvalid(() =>
      buildDcqlQuery([
        mdocCredentialQuery({ id: 'not valid!', doctype: 'd', claims: [{ path: ['d', 'x'] }] }),
      ])
    )
  })

  it('rejects duplicate credential ids', () => {
    expectConfigInvalid(() => buildDcqlQuery([AV_QUERY, AV_QUERY]))
  })

  it('rejects credential_sets options that reference unknown ids', () => {
    expectConfigInvalid(() => buildDcqlQuery([AV_QUERY], [{ options: [['no_such_query']] }]))
  })

  it('rejects a credential set without options', () => {
    expectConfigInvalid(() => buildDcqlQuery([AV_QUERY], [{ options: [] }]))
  })

  it('rejects an empty claims array', () => {
    expectConfigInvalid(() =>
      buildDcqlQuery([{ id: 'q', format: 'mso_mdoc', meta: { doctype_value: 'd' }, claims: [] }])
    )
  })

  it('rejects a claim with an empty path', () => {
    expectConfigInvalid(() =>
      buildDcqlQuery([
        { id: 'q', format: 'dc+sd-jwt', meta: { vct_values: ['v'] }, claims: [{ path: [] }] },
      ])
    )
  })

  it('rejects claim_sets referencing unknown claim ids', () => {
    expectConfigInvalid(() =>
      buildDcqlQuery([
        sdJwtCredentialQuery({
          id: 'q',
          vctValues: ['v'],
          claims: [{ id: 'a', path: ['x'] }],
          claimSets: [['a'], ['ghost']],
        }),
      ])
    )
  })

  it('rejects claim_sets when a claim has no id', () => {
    expectConfigInvalid(() =>
      buildDcqlQuery([
        sdJwtCredentialQuery({
          id: 'q',
          vctValues: ['v'],
          claims: [{ id: 'a', path: ['x'] }, { path: ['y'] }],
          claimSets: [['a']],
        }),
      ])
    )
  })

  it('rejects duplicate claim ids within a credential', () => {
    expectConfigInvalid(() =>
      buildDcqlQuery([
        sdJwtCredentialQuery({
          id: 'q',
          vctValues: ['v'],
          claims: [
            { id: 'a', path: ['x'] },
            { id: 'a', path: ['y'] },
          ],
        }),
      ])
    )
  })
})
