/**
 * `SessionTranscript` and OpenID4VP handover construction for mdoc device authentication.
 *
 * This is the hinge the whole mdoc verification chain turns on. `DeviceSigned.deviceAuth` is a
 * signature over `DeviceAuthentication`, which contains the `SessionTranscript`; if our bytes
 * differ from the wallet's by even one, the device signature check fails and every downstream
 * claim about "verified" is worthless. That is why this module is the first real code in the
 * project and why it is validated against the specification's own hex vectors.
 *
 * Specification: OpenID4VP 1.0 Final (9 July 2025), Appendix B.2.6, on top of ISO 18013-5
 * §9.1.5.1. In both invocation modes the ISO structure is used with:
 *
 * ```
 * SessionTranscript = [ null, null, Handover ]   ; DeviceEngagementBytes and EReaderKeyBytes null
 * ```
 *
 * Two traps live in here, both of which the test vectors pin down:
 *
 *  1. **The hash covers the raw CBOR of the HandoverInfo array — not a `bstr`-wrapped copy of it.**
 *     The CDDL writes `OpenID4VPHandoverInfoBytes = bstr .cbor OpenID4VPHandoverInfo`, which reads
 *     as though the byte-string header were included; it is not. Hashing the wrapped form yields
 *     `a91636ca…` where the spec says `048bc053…`, and the only symptom in production would be a
 *     device signature that never validates.
 *  2. **The origin appears in two places in two different shapes.** In the DC API handover it is
 *     bare (`https://example.com`); in a KB-JWT `aud` it carries the `origin:` prefix. Mixing them
 *     up is the classic source of `InvalidDeviceSignature`.
 */

import { sha256 } from '@noble/hashes/sha2.js'
import { CBOR_NULL, encodeArray, encodeByteString, encodeTextString } from './cbor.js'

/** Fixed identifier of the redirect/QR handover — 17 characters, byte for byte. */
export const OPENID4VP_HANDOVER_TYPE = 'OpenID4VPHandover'

/** Fixed identifier of the Digital Credentials API handover — 22 characters, byte for byte. */
export const OPENID4VP_DCAPI_HANDOVER_TYPE = 'OpenID4VPDCAPIHandover'

/**
 * Inputs for a handover created through redirects (QR, deep link — anything using
 * `direct_post` / `direct_post.jwt`).
 *
 * Every value MUST be taken from the same place the wallet takes it from: the authorization
 * request query parameters when the request is unsigned, or the signed Request Object when it is
 * signed. Writing one value in one place and a different one in the other is the fastest way to
 * a hash that never matches.
 */
export interface OpenID4VPHandoverInput {
  /** The `client_id` request parameter, **including its Client Identifier Prefix**. */
  clientId: string
  /** The `nonce` request parameter. */
  nonce: string
  /**
   * RFC 7638 SHA-256 thumbprint of the public key the verifier published for response
   * encryption, as raw bytes — or `null` when the response is not encrypted.
   *
   * It is not decoration: for unsigned requests it is what lets the verifier **detect** that a
   * third party re-encrypted the response (OpenID4VP §B.2.6.2). We therefore have to check it
   * against our own ephemeral key at verification time, not merely reproduce it here.
   */
  jwkThumbprint: Uint8Array | null
  /** The `redirect_uri` or `response_uri` parameter, whichever the response mode calls for. */
  responseUri: string
}

/** Inputs for a handover created through the W3C Digital Credentials API. */
export interface OpenID4VPDCAPIHandoverInput {
  /**
   * The request's Origin, **without** the `origin:` prefix (e.g. `https://example.com`).
   *
   * Note this is the origin of the top-level traversable's active document — when the verifier
   * runs inside an iframe, that is the *embedding* page's origin, not the frame's.
   */
  origin: string
  /** The `nonce` request parameter. */
  nonce: string
  /** RFC 7638 SHA-256 thumbprint for response mode `dc_api.jwt`; `null` for plain `dc_api`. */
  jwkThumbprint: Uint8Array | null
}

/**
 * `OpenID4VPHandoverInfo` = `[ clientId, nonce, jwkThumbprint, responseUri ]`.
 *
 * Returns the raw CBOR bytes of the array — the exact input to the SHA-256 in
 * {@link buildOpenID4VPHandover}.
 */
export function buildOpenID4VPHandoverInfo(input: OpenID4VPHandoverInput): Uint8Array {
  return encodeArray([
    encodeTextString(input.clientId),
    encodeTextString(input.nonce),
    input.jwkThumbprint === null ? CBOR_NULL : encodeByteString(input.jwkThumbprint),
    encodeTextString(input.responseUri),
  ])
}

/** `OpenID4VPHandover` = `[ "OpenID4VPHandover", sha256(OpenID4VPHandoverInfo) ]`. */
export function buildOpenID4VPHandover(input: OpenID4VPHandoverInput): Uint8Array {
  return encodeArray([
    encodeTextString(OPENID4VP_HANDOVER_TYPE),
    encodeByteString(sha256(buildOpenID4VPHandoverInfo(input))),
  ])
}

/**
 * `OpenID4VPDCAPIHandoverInfo` = `[ origin, nonce, jwkThumbprint ]`.
 *
 * Returns the raw CBOR bytes of the array — the exact input to the SHA-256 in
 * {@link buildOpenID4VPDCAPIHandover}.
 */
export function buildOpenID4VPDCAPIHandoverInfo(input: OpenID4VPDCAPIHandoverInput): Uint8Array {
  return encodeArray([
    encodeTextString(input.origin),
    encodeTextString(input.nonce),
    input.jwkThumbprint === null ? CBOR_NULL : encodeByteString(input.jwkThumbprint),
  ])
}

/** `OpenID4VPDCAPIHandover` = `[ "OpenID4VPDCAPIHandover", sha256(OpenID4VPDCAPIHandoverInfo) ]`. */
export function buildOpenID4VPDCAPIHandover(input: OpenID4VPDCAPIHandoverInput): Uint8Array {
  return encodeArray([
    encodeTextString(OPENID4VP_DCAPI_HANDOVER_TYPE),
    encodeByteString(sha256(buildOpenID4VPDCAPIHandoverInfo(input))),
  ])
}

/**
 * `SessionTranscript` = `[ null, null, Handover ]`, taking an already-encoded handover.
 *
 * Kept separate from the two convenience builders below so that a future handover type
 * (`org-iso-mdoc`'s `dcapi` transcript, ISO 18013-7 Annex C — reserved for v1.1) can reuse it
 * without touching this function.
 */
export function buildSessionTranscript(encodedHandover: Uint8Array): Uint8Array {
  return encodeArray([CBOR_NULL, CBOR_NULL, encodedHandover])
}

/** `SessionTranscript` for a redirect/QR invocation (`direct_post`, `direct_post.jwt`). */
export function buildOpenID4VPSessionTranscript(input: OpenID4VPHandoverInput): Uint8Array {
  return buildSessionTranscript(buildOpenID4VPHandover(input))
}

/** `SessionTranscript` for a Digital Credentials API invocation (`dc_api`, `dc_api.jwt`). */
export function buildOpenID4VPDCAPISessionTranscript(
  input: OpenID4VPDCAPIHandoverInput
): Uint8Array {
  return buildSessionTranscript(buildOpenID4VPDCAPIHandover(input))
}
