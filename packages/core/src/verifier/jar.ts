/**
 * Request Object (JAR) construction — RFC 9101 as profiled by OpenID4VP 1.0 §5.10.
 *
 * The rules pinned here, all of them wallet-enforced:
 *
 *  - The JOSE `typ` header MUST be `oauth-authz-req+jwt`; wallets MUST NOT process anything
 *    else.
 *  - The `redirect_uri` prefix can never sign: the wallet has no way to obtain a trusted key
 *    for it. Signing is therefore inseparable from the `x509_*` prefixes, whose keys travel in
 *    the `x5c` header (leaf first).
 *  - `aud` is the static `https://self-issued.me/v2` — the value OpenID4VP assigns to wallets
 *    reached without dynamic discovery, which is the only mode this release uses.
 *  - The original client id must actually belong to the certificate: for `x509_san_dns` it has
 *    to appear among the leaf's dNSName SANs, for `x509_hash` it IS the base64url SHA-256 of
 *    the leaf. Both are validated at request-creation time — a mismatch would otherwise
 *    surface only as a silent rejection inside the wallet.
 */

import { SignJWT } from 'jose'
import type { ClientIdPrefix } from '../types.js'
import { EudikitError } from '../types.js'
import type { ResolvedSigningKeys, ResolvedVerifierConfig, SigningAlgorithm } from './config.js'

export const REQUEST_OBJECT_TYP = 'oauth-authz-req+jwt'

/** OpenID4VP 1.0 §5.10: the `aud` of a Request Object for wallets without dynamic discovery. */
const REQUEST_OBJECT_AUD = 'https://self-issued.me/v2'

export interface SignedRequestMaterial {
  /** Full client id including its prefix, e.g. `x509_san_dns:verifier.example`. */
  clientId: string
  key: NonNullable<ResolvedSigningKeys['signing']>['key']
  alg: SigningAlgorithm
  /** Standard-base64 chain for the `x5c` header, leaf first. */
  x5c: string[]
}

/**
 * Resolves and validates everything a signed request needs. Throws the config-class errors —
 * always at request creation, never at response time.
 */
export function resolveSignedRequestMaterial(
  config: ResolvedVerifierConfig,
  prefix: ClientIdPrefix
): SignedRequestMaterial {
  if (prefix === 'redirect_uri') {
    // Guarded by the caller; reaching this line is a programming error worth failing loud on.
    throw new EudikitError(
      'CONFIG_INVALID',
      'the redirect_uri prefix cannot be used with signed request objects (OpenID4VP 1.0 §5.10)'
    )
  }

  const signing = config.keys.signing
  if (signing === null) {
    throw new EudikitError(
      'CONFIG_SIGNING_KEY_REQUIRED',
      `the '${prefix}' client id prefix requires a signed request object and no signing key ` +
        'is configured: set keys.requestSigning (PKCS#8 PEM or private JWK) or the ' +
        'EUDIKIT_SIGNING_KEY env var, together with keys.requestSigningCertificateChain. ' +
        "For today's AV wallet, profile 'av' sends unsigned requests and needs no keys at all"
    )
  }
  if (config.keys.chainB64.length === 0) {
    throw new EudikitError(
      'CONFIG_SIGNING_KEY_REQUIRED',
      `the '${prefix}' prefix carries its trust in the x5c header: set ` +
        'keys.requestSigningCertificateChain (leaf certificate first)'
    )
  }

  let originalClientId: string
  if (prefix === 'x509_san_dns') {
    if (config.clientId === null) {
      throw new EudikitError(
        'CONFIG_INVALID',
        "clientIdPrefix 'x509_san_dns' needs config.clientId set to a dNSName that appears " +
          'in the subjectAltName of the leaf certificate'
      )
    }
    if (!config.keys.sanDnsNames.includes(config.clientId)) {
      throw new EudikitError(
        'CONFIG_INVALID',
        `config.clientId "${config.clientId}" is not a dNSName SAN of the leaf certificate ` +
          `(found: ${config.keys.sanDnsNames.length === 0 ? 'none' : config.keys.sanDnsNames.join(', ')}) — ` +
          'the wallet would reject the request'
      )
    }
    originalClientId = config.clientId
  } else {
    // x509_hash: the original client id is a function of the leaf certificate, so it is
    // derived rather than configured; an explicit clientId must agree.
    const derived = config.keys.x509HashClientId
    if (derived === null) {
      throw new EudikitError(
        'CONFIG_SIGNING_KEY_REQUIRED',
        "clientIdPrefix 'x509_hash' needs keys.requestSigningCertificateChain to derive the " +
          'certificate hash from'
      )
    }
    if (config.clientId !== null && config.clientId !== derived) {
      throw new EudikitError(
        'CONFIG_INVALID',
        `config.clientId "${config.clientId}" does not equal the leaf certificate's ` +
          `base64url SHA-256 "${derived}" required by the x509_hash prefix — omit clientId ` +
          'to let the SDK derive it'
      )
    }
    originalClientId = derived
  }

  return {
    clientId: `${prefix}:${originalClientId}`,
    key: signing.key,
    alg: signing.alg,
    x5c: config.keys.chainB64,
  }
}

export interface SignRequestObjectInput {
  material: SignedRequestMaterial
  /**
   * Authorization request parameters as JWT claims — `client_id`, `response_type`, `nonce`,
   * `dcql_query` and friends. `aud`, `iat` and `exp` are set here, not by the caller.
   */
  claims: Record<string, unknown>
  issuedAt: Date
  expiresAt: Date
}

export async function signRequestObject(input: SignRequestObjectInput): Promise<string> {
  return new SignJWT(input.claims)
    .setProtectedHeader({
      alg: input.material.alg,
      typ: REQUEST_OBJECT_TYP,
      x5c: input.material.x5c,
    })
    .setAudience(REQUEST_OBJECT_AUD)
    .setIssuedAt(Math.floor(input.issuedAt.getTime() / 1000))
    .setExpirationTime(Math.floor(input.expiresAt.getTime() / 1000))
    .sign(input.material.key)
}
