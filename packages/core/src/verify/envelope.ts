/**
 * Encrypted-response envelopes (`direct_post.jwt` / `dc_api.jwt`): the wallet's response
 * arrives as a JWE encrypted to the ephemeral key this SDK generated for exactly one request,
 * and this module opens it and reports what the envelope itself proves.
 *
 * What the envelope proves is deliberately limited. OpenID4VP 1.0 §14.5: an encrypted response
 * has no integrity protection of its own — anyone holding the public key could decrypt nothing
 * but *re-encrypt* altered parameters. The defenses, in the order they bite:
 *
 *  - the key is ephemeral and per-request, so possession of the `kid` proves the sender saw
 *    this request's `client_metadata` (`envelope.key_binding`);
 *  - `apv`, when the wallet sets it, ties the key agreement to this request's nonce;
 *  - the decisive binding is the mdoc device signature over a SessionTranscript whose handover
 *    carries the RFC 7638 thumbprint of that same ephemeral key — a re-encrypted envelope can
 *    carry different parameters, but it cannot re-sign the transcript.
 *
 * Decryption accepts exactly what the request advertised: `alg` ECDH-ES, `enc` from
 * `encrypted_response_enc_values_supported`. A wallet that picks anything else produced a
 * response for a different verifier contract, and the failure says so.
 */

import { createPrivateKey } from 'node:crypto'
import { compactDecrypt } from 'jose'
import type { Check, Jwk } from '../types.js'
import { EudikitError } from '../types.js'

/** The `enc` values every encrypted request advertises (and decryption therefore accepts). */
export const SUPPORTED_RESPONSE_ENCRYPTION = ['A128GCM']

export interface OpenEnvelopeInput {
  /** The `response` field: a compact JWE. */
  jwe: string
  /** The session's ephemeral private JWK (carries the RFC 7638 thumbprint as `kid`). */
  privateJwk: Jwk
  /** The request nonce, for the `apv` binding check. */
  nonce: string
}

export type OpenEnvelopeOutcome =
  | { ok: true; payload: Record<string, unknown>; checks: Check[] }
  | { ok: false; error: EudikitError; checks: Check[] }

/**
 * Reads the JWE protected header without any cryptography — the `kid` is how a
 * `direct_post.jwt` response (a lone `response` field, no clear-text `state`) is routed to
 * its session. Returns `null` for anything that is not a five-part compact JWE with a JSON
 * protected header.
 */
export function peekJweKid(jwe: string): string | null {
  const header = decodeProtectedHeader(jwe)
  if (header === null) return null
  return typeof header.kid === 'string' && header.kid !== '' ? header.kid : null
}

export async function openResponseEnvelope(input: OpenEnvelopeInput): Promise<OpenEnvelopeOutcome> {
  const checks: Check[] = []
  const header = decodeProtectedHeader(input.jwe) ?? {}

  let plaintext: Uint8Array
  try {
    const key = createPrivateKey({
      key: input.privateJwk as import('node:crypto').JsonWebKey,
      format: 'jwk',
    })
    ;({ plaintext } = await compactDecrypt(input.jwe, key, {
      keyManagementAlgorithms: ['ECDH-ES'],
      contentEncryptionAlgorithms: SUPPORTED_RESPONSE_ENCRYPTION,
    }))
  } catch (cause) {
    checks.push({
      id: 'envelope.jwe_decrypted',
      status: 'failed',
      detail: `the response JWE did not decrypt with this session's ephemeral key: ${briefly(cause)}`,
    })
    checks.push(keyBindingCheck(header, input))
    return {
      ok: false,
      error: new EudikitError(
        'ENVELOPE_DECRYPTION_FAILED',
        'the encrypted response could not be opened with the ephemeral key generated for ' +
          'this request',
        { cause }
      ),
      checks,
    }
  }

  checks.push({
    id: 'envelope.jwe_decrypted',
    status: 'passed',
    detail: `JWE opened (alg ${String(header.alg)}, enc ${String(header.enc)})`,
  })
  checks.push(keyBindingCheck(header, input))

  let payload: unknown
  try {
    payload = JSON.parse(new TextDecoder().decode(plaintext))
  } catch {
    payload = null
  }
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
    checks.push({
      id: 'envelope.jwe_decrypted',
      status: 'failed',
      detail: 'the JWE plaintext is not a JSON object of response parameters',
    })
    return {
      ok: false,
      error: new EudikitError(
        'PRESENTATION_MALFORMED',
        'the decrypted response is not a JSON object of authorization response parameters'
      ),
      checks,
    }
  }

  return { ok: true, payload: payload as Record<string, unknown>, checks }
}

/**
 * `envelope.key_binding`: the JWE names our key (`kid` mirrors the published JWK's kid — a
 * MUST once the JWK carries one) and, when the wallet sets `apv`, the key agreement is bound
 * to this request's nonce. The thumbprint half of the binding lives in the SessionTranscript
 * handover and is enforced by the device-signature check, not here.
 */
function keyBindingCheck(header: Record<string, unknown>, input: OpenEnvelopeInput): Check {
  const problems: string[] = []
  const facts: string[] = []

  if (typeof header.kid !== 'string' || header.kid === '') {
    problems.push('the JWE header carries no kid although the published JWK has one')
  } else if (header.kid !== input.privateJwk.kid) {
    problems.push('the JWE kid does not name the ephemeral key published for this request')
  } else {
    facts.push('kid matches the per-request ephemeral key')
  }

  if (typeof header.apv === 'string' && header.apv !== '') {
    if (header.apv === base64UrlOfUtf8(input.nonce)) {
      facts.push('apv is bound to the request nonce')
    } else {
      problems.push('apv does not encode the request nonce')
    }
  } else {
    facts.push('no apv sent (optional)')
  }

  return {
    id: 'envelope.key_binding',
    status: problems.length === 0 ? 'passed' : 'failed',
    detail:
      problems.length === 0
        ? `${facts.join('; ')}; the jwkThumbprint binding is enforced by the device signature ` +
          'over the rebuilt SessionTranscript'
        : problems.join('; '),
  }
}

function decodeProtectedHeader(jwe: string): Record<string, unknown> | null {
  if (typeof jwe !== 'string') return null
  const parts = jwe.split('.')
  if (parts.length !== 5 || parts[0] === '') return null
  try {
    const header = JSON.parse(Buffer.from(parts[0] as string, 'base64url').toString('utf8'))
    return typeof header === 'object' && header !== null
      ? (header as Record<string, unknown>)
      : null
  } catch {
    return null
  }
}

function base64UrlOfUtf8(value: string): string {
  return Buffer.from(value, 'utf8').toString('base64url')
}

function briefly(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause)
}
