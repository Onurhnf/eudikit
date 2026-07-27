/**
 * Wallet-side JWE construction for the encrypted-response tests. `apu`/`apv` go through
 * `setKeyManagementParameters` — that is what feeds the ECDH-ES Concat KDF *and* writes the
 * header parameters; setting them on the protected header by hand desynchronizes the KDF and
 * produces envelopes nobody can open.
 */

import { CompactEncrypt, importJWK } from 'jose'

export interface EncryptResponseOptions {
  payload: Record<string, unknown>
  /** The verifier's ephemeral public JWK, exactly as published in `client_metadata.jwks`. */
  recipientJwk: Record<string, unknown>
  /** Header `kid`; defaults to the recipient JWK's own kid. */
  kid?: string
  /** UTF-8 source of `apv` (the request nonce); omitted → no apv. */
  apv?: string
  enc?: string
}

export async function encryptWalletResponse(options: EncryptResponseOptions): Promise<string> {
  const kid = options.kid ?? (options.recipientJwk.kid as string)
  const encrypt = new CompactEncrypt(
    new TextEncoder().encode(JSON.stringify(options.payload))
  ).setProtectedHeader({
    alg: 'ECDH-ES',
    enc: options.enc ?? 'A128GCM',
    ...(kid !== undefined ? { kid } : {}),
  })
  if (options.apv !== undefined) {
    encrypt.setKeyManagementParameters({ apv: Buffer.from(options.apv, 'utf8') })
  }
  return encrypt.encrypt(
    await importJWK(options.recipientJwk as Parameters<typeof importJWK>[0], 'ECDH-ES')
  )
}
