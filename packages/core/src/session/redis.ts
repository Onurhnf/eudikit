import type { RedisLikeClient, SessionAdapter, StoredRecord } from '../types.js'
import { EudikitError } from '../types.js'

/**
 * Atomic read-and-delete for servers without `GETDEL` (Redis < 6.2, and some hosted
 * offerings). Runs as a single script, so it has the same one-winner guarantee.
 */
const GET_THEN_DEL = `local value = redis.call('GET', KEYS[1])
if value then redis.call('DEL', KEYS[1]) end
return value`

function parseRecord(value: unknown): StoredRecord | null {
  return typeof value === 'string' ? (JSON.parse(value) as StoredRecord) : null
}

/**
 * Session adapter over any Redis-compatible client (node-redis, ioredis wrappers, Upstash).
 *
 * The client is typed structurally so no Redis library type ever appears in the public API.
 * `consume()` uses `GETDEL` when the client exposes it and falls back to an `EVAL` script
 * otherwise; a client offering neither cannot provide an atomic single-use read, so the
 * factory refuses it up front instead of degrading silently.
 *
 * Session records contain an ephemeral **private** JWK, so the store connection needs TLS and
 * authentication in production.
 */
export function redisSessionAdapter(
  client: RedisLikeClient,
  opts?: { keyPrefix?: string }
): SessionAdapter {
  if (typeof client.getdel !== 'function' && typeof client.eval !== 'function') {
    throw new EudikitError(
      'CONFIG_INVALID',
      'redisSessionAdapter needs a client with getdel() or eval(): consume() must be an atomic ' +
        'read-and-delete, and a plain GET + DEL pair cannot guarantee that.'
    )
  }

  const prefix = opts?.keyPrefix ?? 'eudikit:'
  const prefixed = (key: string): string => prefix + key

  return {
    async set(key, record, ttlSeconds) {
      await client.set(prefixed(key), JSON.stringify(record), { EX: ttlSeconds })
    },

    async consume(key) {
      if (typeof client.getdel === 'function') {
        return parseRecord(await client.getdel(prefixed(key)))
      }
      if (typeof client.eval === 'function') {
        return parseRecord(await client.eval(GET_THEN_DEL, [prefixed(key)], []))
      }
      // Unreachable: the constructor rejected clients with neither capability.
      throw new EudikitError('INTERNAL', 'redis client lost its getdel/eval capability')
    },

    async get(key) {
      return parseRecord(await client.get(prefixed(key)))
    },

    async delete(key) {
      await client.del(prefixed(key))
    },
  }
}
