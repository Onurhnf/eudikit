import { buildDcqlQuery, mdocCredentialQuery, sdJwtCredentialQuery } from '../dcql/build.js'
import type { CountryClaims, CountryOptions, PresetDefinition } from '../types.js'
import { EudikitError } from '../types.js'
import { asStringSet, malformed, nestedClaim } from './claims.js'

const EU_PID_VCT = 'urn:eudi:pid:1'
const EU_PID_MDOC_DOCTYPE = 'eu.europa.ec.eudi.pid.1'

/**
 * Country preset. `attribute` is mandatory because nationality and country of residence answer
 * different legal questions, and a silent default would let an integrator enforce the wrong one.
 *
 * The extracted value is always a set: the PID Rulebook types the mdoc `nationality` attribute
 * as an array, so even a single nationality arrives as a one-element list, and business rules
 * must be written as "set ∩ allowed countries", never "nationality == X". The rulebook's
 * reserved codes `QU` (unknown) and `QS` (stateless) pass through unchanged so that a gate
 * sees them and decides, instead of the library silently producing a false negative.
 */
export function country(options: CountryOptions): PresetDefinition<CountryClaims> {
  const attribute = options?.attribute
  if (attribute !== 'nationality' && attribute !== 'residence') {
    throw new EudikitError(
      'CONFIG_INVALID',
      'presets.country requires attribute: "nationality" | "residence" — the two are different ' +
        'business rules (licence geography wants residence, content rules want nationality), ' +
        'so there is no default'
    )
  }

  const sdJwtPath = attribute === 'nationality' ? ['nationalities', null] : ['address', 'country']
  const mdocClaim = attribute === 'nationality' ? 'nationality' : 'resident_country'

  const dcql = buildDcqlQuery(
    [
      sdJwtCredentialQuery({
        id: 'pid_sdjwt_country',
        vctValues: [EU_PID_VCT],
        claims: [{ path: sdJwtPath }],
      }),
      mdocCredentialQuery({
        id: 'pid_mdoc_country',
        doctype: EU_PID_MDOC_DOCTYPE,
        claims: [{ path: [EU_PID_MDOC_DOCTYPE, mdocClaim] }],
      }),
    ],
    [{ options: [['pid_sdjwt_country'], ['pid_mdoc_country']] }]
  )

  // `["nationalities", null]` selects all elements of the array; for reading the extracted
  // value we address the array itself, so the trailing null is dropped.
  const sdJwtReadPath = sdJwtPath.filter((segment): segment is string => segment !== null)

  const readers: Array<{ queryId: string; read: (claims: Record<string, unknown>) => unknown }> = [
    { queryId: 'pid_sdjwt_country', read: (claims) => nestedClaim(claims, sdJwtReadPath) },
    { queryId: 'pid_mdoc_country', read: (claims) => claims[mdocClaim] },
  ]

  return {
    id: 'country',
    dcql,
    extract: (verified) => {
      for (const { queryId, read } of readers) {
        const credential = verified.find((entry) => entry.queryId === queryId)
        if (credential === undefined) continue
        const value = read(credential.claims)
        if (value === undefined) {
          malformed(`credential "${queryId}" is missing the requested ${attribute} claim`)
        }
        return { attribute, countries: asStringSet(value, `the ${attribute} claim`) }
      }
      malformed('no credential in the presentation matches the country preset query')
    },
  }
}
