/**
 * Per-request ephemeral response-encryption keys.
 *
 * For every encrypted flow the verifier publishes a fresh P-256 key in `client_metadata.jwks`
 * and the wallet encrypts its response to it. Generating the pair inside the SDK — instead of
 * accepting a long-lived key via config — is what makes the response-re-encryption defense of
 * OpenID4VP 1.0 §14.5 work: the private half lives only in the session record and dies with it.
 *
 * The `kid` is the RFC 7638 SHA-256 thumbprint of the public key, base64url-encoded. That is
 * deliberate double duty: the mdoc SessionTranscript handover binds the same thumbprint bytes
 * (`jwkThumbprint` in `../mdoc/session-transcript.ts`), so at verification time the handover can
 * be rebuilt from the stored session key alone — base64url-decode the kid and the key-binding
 * check has its bytes.
 */

import { calculateJwkThumbprint, exportJWK, generateKeyPair } from 'jose'
import type { Jwk } from '../types.js'
import { EudikitError } from '../types.js'

export interface EphemeralEncryptionKeyPair {
  /** Public half — goes into `client_metadata.jwks.keys` and nowhere else. */
  publicJwk: Jwk
  /** Private half — goes into the session record and nowhere else. */
  privateJwk: Jwk
}

export async function generateEphemeralEncryptionKey(): Promise<EphemeralEncryptionKeyPair> {
  const { publicKey, privateKey } = await generateKeyPair('ECDH-ES', {
    crv: 'P-256',
    extractable: true,
  })
  const publicJwk = await exportJWK(publicKey)
  const privateJwk = await exportJWK(privateKey)
  const kid = await calculateJwkThumbprint(publicJwk)
  return {
    publicJwk: withKeyMetadata(publicJwk, kid),
    privateJwk: withKeyMetadata(privateJwk, kid),
  }
}

function withKeyMetadata(jwk: { kty?: string }, kid: string): Jwk {
  if (typeof jwk.kty !== 'string') {
    throw new EudikitError('INTERNAL', 'key export produced a JWK without a kty')
  }
  return { ...jwk, kty: jwk.kty, kid, use: 'enc', alg: 'ECDH-ES' }
}
