import type { SessionAdapter, StoredRecord } from '../types.js'

interface Entry {
  /** JSON text, not the live object — see the note on serialization below. */
  value: string
  /** Epoch milliseconds; entries at or past this instant no longer exist. */
  expiresAt: number
}

let instances = 0
let warned = false

function warnOnce(): void {
  if (warned) return
  warned = true
  console.warn(
    '[eudikit] memorySessionAdapter stores sessions per process. With more than one process ' +
      '(serverless, clusters, rolling deploys) a wallet response can land on an instance that ' +
      'never saw the request. Use redisSessionAdapter() or kvSessionAdapter() in production.'
  )
}

/**
 * In-memory session adapter for a single long-lived process — local development, tests, demos.
 *
 * Records are pushed through JSON on `set` and parsed back on read, so the development adapter
 * has exactly the semantics of the Redis/KV adapters: no shared references, and a record that
 * cannot survive JSON serialization fails here first instead of in production.
 *
 * `consume()` is atomic by construction: the lookup and the delete happen in one synchronous
 * step, and JavaScript never interleaves synchronous code, so of two racing calls exactly one
 * receives the record.
 *
 * Expired entries are dropped lazily on access, plus in an amortized sweep whenever the store
 * has doubled since the last sweep — no timer is kept alive.
 */
export function memorySessionAdapter(): SessionAdapter {
  instances += 1
  if (instances > 1 || globalThis.process?.env?.NODE_ENV === 'production') warnOnce()

  const store = new Map<string, Entry>()
  let sweepAt = 64

  const liveEntry = (key: string): Entry | null => {
    const entry = store.get(key)
    if (entry === undefined) return null
    if (entry.expiresAt <= Date.now()) {
      store.delete(key)
      return null
    }
    return entry
  }

  const sweep = (): void => {
    if (store.size < sweepAt) return
    const now = Date.now()
    for (const [key, entry] of store) {
      if (entry.expiresAt <= now) store.delete(key)
    }
    sweepAt = Math.max(64, store.size * 2)
  }

  return {
    async set(key, record, ttlSeconds) {
      sweep()
      store.set(key, {
        value: JSON.stringify(record),
        expiresAt: Date.now() + ttlSeconds * 1000,
      })
    },

    async consume(key) {
      const entry = liveEntry(key)
      if (entry === null) return null
      store.delete(key)
      return JSON.parse(entry.value) as StoredRecord
    },

    async get(key) {
      const entry = liveEntry(key)
      return entry === null ? null : (JSON.parse(entry.value) as StoredRecord)
    },

    async delete(key) {
      store.delete(key)
    },
  }
}
