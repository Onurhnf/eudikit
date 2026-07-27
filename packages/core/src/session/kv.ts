import type { KvLikeClient, SessionAdapter, StoredRecord } from '../types.js'

let warned = false

function warnOnce(): void {
  if (warned) return
  warned = true
  console.warn(
    '[eudikit] kvSessionAdapter: KV stores of this shape (Cloudflare Workers KV and friends) ' +
      'are eventually consistent and have no atomic read-and-delete, so consume() cannot ' +
      'guarantee that a session is used exactly once across locations. For single-use ' +
      'nonces prefer redisSessionAdapter() (Redis/Upstash) or a strongly consistent store.'
  )
}

/**
 * Session adapter over a Workers-KV-shaped store (`get`/`put`/`delete` + `expirationTtl`).
 *
 * `consume()` here is a read followed by a delete — NOT atomic, because the KV interface has
 * no primitive to make it so, and eventual consistency means two locations can both read a
 * key before either delete propagates. That weakens the single-use guarantee the session
 * protocol wants, which is why the factory says so out loud once per process rather than
 * letting the gap surface as a replay incident.
 *
 * Session records contain an ephemeral **private** JWK, so the store binding needs to be
 * scoped and authenticated like any other secret store in production.
 */
export function kvSessionAdapter(kv: KvLikeClient, opts?: { keyPrefix?: string }): SessionAdapter {
  warnOnce()

  const prefix = opts?.keyPrefix ?? 'eudikit:'
  const prefixed = (key: string): string => prefix + key

  const read = async (key: string): Promise<StoredRecord | null> => {
    const value = await kv.get(prefixed(key))
    return typeof value === 'string' ? (JSON.parse(value) as StoredRecord) : null
  }

  return {
    async set(key, record, ttlSeconds) {
      await kv.put(prefixed(key), JSON.stringify(record), { expirationTtl: ttlSeconds })
    },

    async consume(key) {
      const record = await read(key)
      if (record === null) return null
      await kv.delete(prefixed(key))
      return record
    },

    async get(key) {
      return read(key)
    },

    async delete(key) {
      await kv.delete(prefixed(key))
    },
  }
}
