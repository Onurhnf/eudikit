import { createVerifier, memorySessionAdapter, type Verifier } from '@eudikit/core'

/**
 * One verifier for the whole app.
 *
 * `profile: 'av'` is the wallet world this demo targets: unsigned by-value requests carried in a
 * deep link or a QR code, answered with an unencrypted `direct_post`. No signing key is needed,
 * which is why this file is as short as it is.
 *
 * `publicBaseUrl` is the one setting that must be right. The wallet runs on a phone, so it has
 * to reach this server over public HTTPS — point `EUDIKIT_PUBLIC_BASE_URL` at your tunnel (see
 * the README). Without it, request creation fails loudly rather than producing a URL nothing can
 * reach.
 *
 * The in-memory session store is fine for a demo on one machine and wrong for anything with more
 * than one instance; production deployments pass `redisSessionAdapter(...)` or
 * `kvSessionAdapter(...)` instead.
 */

const publicBaseUrl = process.env.EUDIKIT_PUBLIC_BASE_URL
const trustMode = process.env.EUDIKIT_TRUST_MODE === 'permissive' ? 'permissive' : 'strict'

/**
 * PEM certificates, newline-separated, for a local issuer that is not on the AV trusted list —
 * a testbed convenience. Anchors are additive: the trusted list still applies.
 */
const additionalTrustAnchors = splitPem(process.env.EUDIKIT_TRUST_ANCHORS)

function build(): Verifier {
  return createVerifier({
    profile: 'av',
    ...(publicBaseUrl !== undefined ? { publicBaseUrl } : {}),
    session: memorySessionAdapter(),
    trust: {
      mode: trustMode,
      avTrustedList: true,
      ...(additionalTrustAnchors.length > 0 ? { additionalTrustAnchors } : {}),
    },
  })
}

// Next reloads route modules on every edit in development; a fresh verifier each time would
// throw away the sessions of a request that is already on a phone.
const globalForEudikit = globalThis as typeof globalThis & {
  eudikitVerifier?: Verifier
}

export const verifier: Verifier = globalForEudikit.eudikitVerifier ?? build()

if (process.env.NODE_ENV !== 'production') {
  globalForEudikit.eudikitVerifier = verifier
}

function splitPem(value: string | undefined): string[] {
  if (value === undefined || value.trim() === '') return []
  return value
    .split(/(?=-----BEGIN CERTIFICATE-----)/)
    .map((pem) => pem.trim())
    .filter((pem) => pem !== '')
}
