/**
 * Session adapter contract tests.
 *
 * The property under test everywhere is the same one the response protocol depends on:
 * `consume()` is a single-use read. For the in-memory adapter that is exercised as a real
 * race (two overlapping consumes); for the Redis adapter the fakes pin down which primitive
 * (`GETDEL` vs `EVAL`) implements the atomicity; for the KV adapter the point is the opposite —
 * the interface cannot be atomic, and the adapter must say so.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { kvSessionAdapter } from '../src/session/kv.js'
import { memorySessionAdapter } from '../src/session/memory.js'
import { redisSessionAdapter } from '../src/session/redis.js'
import type { KvLikeClient, RedisLikeClient } from '../src/types.js'
import { EudikitError } from '../src/types.js'

beforeEach(() => {
  vi.useFakeTimers()
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})

afterEach(() => {
  vi.useRealTimers()
  vi.restoreAllMocks()
  vi.unstubAllEnvs()
})

// ---------------------------------------------------------------------------
// memorySessionAdapter
// ---------------------------------------------------------------------------

describe('memorySessionAdapter', () => {
  it('stores and returns a record', async () => {
    const adapter = memorySessionAdapter()
    await adapter.set('sess', { nonce: 'abc' }, 60)
    expect(await adapter.get('sess')).toEqual({ nonce: 'abc' })
    expect(await adapter.get('missing')).toBeNull()
  })

  it('returns copies, never live references', async () => {
    const adapter = memorySessionAdapter()
    const record = { nonce: 'abc' }
    await adapter.set('sess', record, 60)
    record.nonce = 'mutated-after-set'
    const first = await adapter.get('sess')
    expect(first).toEqual({ nonce: 'abc' })
    if (first === null) throw new Error('unreachable')
    first.nonce = 'mutated-after-get'
    expect(await adapter.get('sess')).toEqual({ nonce: 'abc' })
  })

  it('consume returns the record exactly once', async () => {
    const adapter = memorySessionAdapter()
    await adapter.set('sess', { nonce: 'abc' }, 60)
    expect(await adapter.consume('sess')).toEqual({ nonce: 'abc' })
    expect(await adapter.consume('sess')).toBeNull()
    expect(await adapter.get('sess')).toBeNull()
  })

  it('lets exactly one of two racing consumes win', async () => {
    const adapter = memorySessionAdapter()
    await adapter.set('sess', { nonce: 'abc' }, 60)
    const results = await Promise.all([adapter.consume('sess'), adapter.consume('sess')])
    expect(results.filter((record) => record !== null)).toHaveLength(1)
  })

  it('expires records after their TTL', async () => {
    const adapter = memorySessionAdapter()
    await adapter.set('sess', { nonce: 'abc' }, 60)
    vi.advanceTimersByTime(59_999)
    expect(await adapter.get('sess')).toEqual({ nonce: 'abc' })
    vi.advanceTimersByTime(2)
    expect(await adapter.get('sess')).toBeNull()
    expect(await adapter.consume('sess')).toBeNull()
  })

  it('delete removes the record', async () => {
    const adapter = memorySessionAdapter()
    await adapter.set('sess', { nonce: 'abc' }, 60)
    await adapter.delete('sess')
    expect(await adapter.consume('sess')).toBeNull()
  })

  it('warns once when more than one instance is created', async () => {
    vi.resetModules()
    const fresh = await import('../src/session/memory.js')
    const warn = vi.mocked(console.warn)
    warn.mockClear()

    fresh.memorySessionAdapter()
    expect(warn).not.toHaveBeenCalled()
    fresh.memorySessionAdapter()
    expect(warn).toHaveBeenCalledTimes(1)
    fresh.memorySessionAdapter()
    expect(warn).toHaveBeenCalledTimes(1)
    expect(warn.mock.calls[0]?.[0]).toContain('memorySessionAdapter')
  })

  it('warns on the first instance when NODE_ENV is production', async () => {
    vi.resetModules()
    vi.stubEnv('NODE_ENV', 'production')
    const fresh = await import('../src/session/memory.js')
    const warn = vi.mocked(console.warn)
    warn.mockClear()

    fresh.memorySessionAdapter()
    expect(warn).toHaveBeenCalledTimes(1)
  })
})

// ---------------------------------------------------------------------------
// redisSessionAdapter
// ---------------------------------------------------------------------------

interface FakeRedis {
  client: RedisLikeClient
  entries: Map<string, { value: string; expiresAt: number | null }>
  getdel: ReturnType<typeof vi.fn> | null
  eval: ReturnType<typeof vi.fn> | null
}

/**
 * Map-backed Redis fake with expiry checked on read. `getdel` and `eval` are individually
 * removable so both consume paths can be pinned down; the `eval` fake implements the
 * GET-then-DEL semantics of the adapter's script rather than interpreting Lua.
 */
function createFakeRedis(features: { getdel: boolean; eval: boolean }): FakeRedis {
  const entries = new Map<string, { value: string; expiresAt: number | null }>()

  const live = (key: string): string | null => {
    const entry = entries.get(key)
    if (entry === undefined) return null
    if (entry.expiresAt !== null && entry.expiresAt <= Date.now()) {
      entries.delete(key)
      return null
    }
    return entry.value
  }

  const client: RedisLikeClient = {
    async get(key) {
      return live(key)
    },
    async set(key, value, opts) {
      const expiresAt = opts?.EX !== undefined ? Date.now() + opts.EX * 1000 : null
      entries.set(key, { value, expiresAt })
    },
    async del(key) {
      entries.delete(key)
    },
  }

  let getdel: FakeRedis['getdel'] = null
  if (features.getdel) {
    getdel = vi.fn(async (key: string) => {
      const value = live(key)
      entries.delete(key)
      return value
    })
    client.getdel = getdel as unknown as NonNullable<RedisLikeClient['getdel']>
  }

  let evalFn: FakeRedis['eval'] = null
  if (features.eval) {
    evalFn = vi.fn(async (_script: string, keys: string[], _args: string[]) => {
      const key = keys[0] ?? ''
      const value = live(key)
      if (value !== null) entries.delete(key)
      return value
    })
    client.eval = evalFn as unknown as NonNullable<RedisLikeClient['eval']>
  }

  return { client, entries, getdel, eval: evalFn }
}

describe('redisSessionAdapter', () => {
  it('writes JSON with a TTL under the default key prefix', async () => {
    const fake = createFakeRedis({ getdel: true, eval: true })
    const adapter = redisSessionAdapter(fake.client)
    await adapter.set('sess', { nonce: 'abc' }, 60)

    const entry = fake.entries.get('eudikit:sess')
    expect(entry).toBeDefined()
    expect(JSON.parse(entry?.value ?? '')).toEqual({ nonce: 'abc' })

    vi.advanceTimersByTime(60_001)
    expect(await adapter.get('sess')).toBeNull()
  })

  it('honors a custom key prefix', async () => {
    const fake = createFakeRedis({ getdel: true, eval: true })
    const adapter = redisSessionAdapter(fake.client, { keyPrefix: 'acme:' })
    await adapter.set('sess', { nonce: 'abc' }, 60)
    expect(fake.entries.has('acme:sess')).toBe(true)
  })

  it('consumes through GETDEL when the client offers it', async () => {
    const fake = createFakeRedis({ getdel: true, eval: true })
    const adapter = redisSessionAdapter(fake.client)
    await adapter.set('sess', { nonce: 'abc' }, 60)

    expect(await adapter.consume('sess')).toEqual({ nonce: 'abc' })
    expect(fake.getdel).toHaveBeenCalledWith('eudikit:sess')
    expect(fake.eval).not.toHaveBeenCalled()
    expect(await adapter.consume('sess')).toBeNull()
  })

  it('falls back to the EVAL script when GETDEL is missing', async () => {
    const fake = createFakeRedis({ getdel: false, eval: true })
    const adapter = redisSessionAdapter(fake.client)
    await adapter.set('sess', { nonce: 'abc' }, 60)

    expect(await adapter.consume('sess')).toEqual({ nonce: 'abc' })
    expect(fake.eval).toHaveBeenCalledTimes(1)
    expect(fake.eval?.mock.calls[0]?.[1]).toEqual(['eudikit:sess'])
    // The fake cannot run Lua, so the atomicity claim rests on the script text itself: one
    // round trip that reads and deletes the same key. A fake that reimplements the semantics
    // would otherwise be proving its own behaviour rather than the adapter's.
    const script = String(fake.eval?.mock.calls[0]?.[0])
    expect(script).toContain("redis.call('GET', KEYS[1])")
    expect(script).toContain("redis.call('DEL', KEYS[1])")
    expect(await adapter.consume('sess')).toBeNull()
    expect(await adapter.get('sess')).toBeNull()
  })

  it('rejects a client with neither GETDEL nor EVAL', () => {
    const fake = createFakeRedis({ getdel: false, eval: false })
    try {
      redisSessionAdapter(fake.client)
      expect.unreachable('expected redisSessionAdapter to throw')
    } catch (error) {
      expect(error).toBeInstanceOf(EudikitError)
      expect((error as EudikitError).code).toBe('CONFIG_INVALID')
    }
  })

  it('get is non-destructive', async () => {
    const fake = createFakeRedis({ getdel: true, eval: true })
    const adapter = redisSessionAdapter(fake.client)
    await adapter.set('sess', { nonce: 'abc' }, 60)
    expect(await adapter.get('sess')).toEqual({ nonce: 'abc' })
    expect(await adapter.get('sess')).toEqual({ nonce: 'abc' })
  })

  it('does not consume expired records', async () => {
    const fake = createFakeRedis({ getdel: true, eval: true })
    const adapter = redisSessionAdapter(fake.client)
    await adapter.set('sess', { nonce: 'abc' }, 60)
    vi.advanceTimersByTime(60_001)
    expect(await adapter.consume('sess')).toBeNull()
  })

  it('delete removes the record', async () => {
    const fake = createFakeRedis({ getdel: true, eval: true })
    const adapter = redisSessionAdapter(fake.client)
    await adapter.set('sess', { nonce: 'abc' }, 60)
    await adapter.delete('sess')
    expect(await adapter.get('sess')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// kvSessionAdapter
// ---------------------------------------------------------------------------

function createFakeKv(): {
  kv: KvLikeClient
  entries: Map<string, { value: string; expiresAt: number | null }>
} {
  const entries = new Map<string, { value: string; expiresAt: number | null }>()
  const kv: KvLikeClient = {
    async get(key) {
      const entry = entries.get(key)
      if (entry === undefined) return null
      if (entry.expiresAt !== null && entry.expiresAt <= Date.now()) {
        entries.delete(key)
        return null
      }
      return entry.value
    },
    async put(key, value, opts) {
      const expiresAt =
        opts?.expirationTtl !== undefined ? Date.now() + opts.expirationTtl * 1000 : null
      entries.set(key, { value, expiresAt })
    },
    async delete(key) {
      entries.delete(key)
    },
  }
  return { kv, entries }
}

describe('kvSessionAdapter', () => {
  it('stores under the default prefix and expires with expirationTtl', async () => {
    const fake = createFakeKv()
    const adapter = kvSessionAdapter(fake.kv)
    await adapter.set('sess', { nonce: 'abc' }, 60)

    expect(fake.entries.has('eudikit:sess')).toBe(true)
    expect(await adapter.get('sess')).toEqual({ nonce: 'abc' })
    vi.advanceTimersByTime(60_001)
    expect(await adapter.get('sess')).toBeNull()
  })

  it('consume returns the record and deletes it', async () => {
    const fake = createFakeKv()
    const adapter = kvSessionAdapter(fake.kv)
    await adapter.set('sess', { nonce: 'abc' }, 60)
    expect(await adapter.consume('sess')).toEqual({ nonce: 'abc' })
    expect(await adapter.get('sess')).toBeNull()
    expect(await adapter.consume('missing')).toBeNull()
  })

  it('warns once per process about the missing consume atomicity', async () => {
    vi.resetModules()
    const fresh = await import('../src/session/kv.js')
    const warn = vi.mocked(console.warn)
    warn.mockClear()

    fresh.kvSessionAdapter(createFakeKv().kv)
    fresh.kvSessionAdapter(createFakeKv().kv)
    expect(warn).toHaveBeenCalledTimes(1)
    expect(warn.mock.calls[0]?.[0]).toContain('kvSessionAdapter')
  })
})
