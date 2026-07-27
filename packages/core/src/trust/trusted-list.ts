/**
 * The AV trusted-list source: fetching, caching and freshness of the ETSI TS 119 612 XML that
 * the trust checks evaluate against.
 *
 * Freshness contract (no silent staleness, ever):
 *
 *  - `refreshIntervalSeconds` is the re-fetch cadence: a copy younger than that is served
 *    without touching the network.
 *  - When a refresh is due and the fetch succeeds, the new copy replaces the cached one and is
 *    fresh by definition — nothing more current exists.
 *  - When the fetch (or the parse of its body) fails, the cached copy is still authoritative
 *    until the moment the list itself declares: a list stays valid until its own `NextUpdate`,
 *    which is the validity statement the scheme operator publishes it with (ETSI TS 119 612
 *    §5.3.14). Inside that window the snapshot reports `fresh: true` and names the failed
 *    refresh in its detail; past it — or with no `NextUpdate` to go on — the copy is still used
 *    for matching but reports `fresh: false`, which surfaces as a failed `trust.list_fresh`
 *    check: strict mode rejects, permissive mode warns.
 *  - With no cached copy at all, the snapshot reports `available: false`; membership cannot be
 *    evaluated and strict verification fails with `TRUSTED_LIST_UNAVAILABLE`.
 *
 * A corrupted download can never replace a good cache: the body is parsed before the cache is
 * written.
 *
 * The list's own XAdES signature is deliberately not verified in this release (the
 * `trust.list_signature_valid` check reports `skipped`); transport security rests on HTTPS.
 */

import type { SessionAdapter, TrustCacheAdapter } from '../types.js'
import { parseTrustedListXml, type TrustedListService } from './etsi-trusted-list.js'

export interface TrustedListSnapshot {
  /** False when neither the network nor the cache produced a usable list. */
  available: boolean
  /** True when the served copy is younger than the refresh interval. */
  fresh: boolean
  services: TrustedListService[]
  fetchedAt: Date | null
  /** Human-readable provenance or failure description for the check rows. Never carries PII. */
  detail: string
}

export interface TrustedListSourceOptions {
  url: string
  refreshIntervalSeconds: number
  cache: TrustCacheAdapter
  fetch: typeof fetch
}

/** How long a downloaded copy is kept in the cache store; not a freshness rule. */
const CACHE_RETENTION_SECONDS = 30 * 24 * 3600

interface CachedList {
  v: 2
  fetchedAt: string
  sequenceNumber: number | null
  listIssueDateTime: string | null
  nextUpdate: string | null
  services: Array<{
    tspName: string
    serviceName: string
    serviceTypeIdentifier: string
    status: string
    certificates: string[]
  }>
}

export class TrustedListSource {
  private readonly options: TrustedListSourceOptions
  private readonly cacheKey: string
  private inflight: Promise<CachedList> | null = null

  constructor(options: TrustedListSourceOptions) {
    this.options = options
    this.cacheKey = `trust:av-tl:${options.url}`
  }

  /** Never throws — every failure mode is expressed in the snapshot. */
  async getSnapshot(now: Date): Promise<TrustedListSnapshot> {
    const cached = await this.readCache()
    if (cached !== null && this.age(cached, now) < this.options.refreshIntervalSeconds) {
      return this.snapshot(cached, true)
    }

    try {
      const refreshed = await this.refresh(now)
      return this.snapshot(refreshed, true)
    } catch (cause) {
      const reason = cause instanceof Error ? cause.message : String(cause)
      if (cached !== null) {
        const withinValidity = validUntil(cached) > now.getTime()
        const served = this.snapshot(cached, withinValidity)
        served.detail = withinValidity
          ? `refresh from ${this.options.url} failed (${reason}); the copy fetched ` +
            `${cached.fetchedAt} is still valid — the list declares NextUpdate ${cached.nextUpdate}`
          : `refresh from ${this.options.url} failed (${reason}); serving the copy fetched ` +
            `${cached.fetchedAt}, whose declared NextUpdate (${cached.nextUpdate ?? 'absent'}) ` +
            'has passed'
        return served
      }
      return {
        available: false,
        fresh: false,
        services: [],
        fetchedAt: null,
        detail: `fetching ${this.options.url} failed (${reason}) and no cached copy exists`,
      }
    }
  }

  /** One network fetch at a time; concurrent verifications share the same refresh. */
  private refresh(now: Date): Promise<CachedList> {
    if (this.inflight === null) {
      this.inflight = this.fetchAndStore(now).finally(() => {
        this.inflight = null
      })
    }
    return this.inflight
  }

  private async fetchAndStore(now: Date): Promise<CachedList> {
    const response = await this.options.fetch(this.options.url, {
      headers: { accept: 'application/xml' },
    })
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`)
    }
    const parsed = parseTrustedListXml(await response.text())
    const record: CachedList = {
      v: 2,
      fetchedAt: now.toISOString(),
      sequenceNumber: parsed.sequenceNumber,
      listIssueDateTime: parsed.listIssueDateTime,
      nextUpdate: parsed.nextUpdate,
      services: parsed.services.map((service) => ({
        tspName: service.tspName,
        serviceName: service.serviceName,
        serviceTypeIdentifier: service.serviceTypeIdentifier,
        status: service.status,
        certificates: service.certificates.map((der) => Buffer.from(der).toString('base64')),
      })),
    }
    await this.options.cache.set(this.cacheKey, JSON.stringify(record), CACHE_RETENTION_SECONDS)
    return record
  }

  private async readCache(): Promise<CachedList | null> {
    let raw: string | null
    try {
      raw = await this.options.cache.get(this.cacheKey)
    } catch {
      return null
    }
    if (raw === null) return null
    try {
      const record = JSON.parse(raw) as CachedList
      if (record.v !== 2 || !Array.isArray(record.services)) return null
      return record
    } catch {
      return null
    }
  }

  private age(cached: CachedList, now: Date): number {
    const fetchedAt = Date.parse(cached.fetchedAt)
    if (Number.isNaN(fetchedAt)) return Number.POSITIVE_INFINITY
    return (now.getTime() - fetchedAt) / 1000
  }

  private snapshot(cached: CachedList, fresh: boolean): TrustedListSnapshot {
    return {
      available: true,
      fresh,
      services: cached.services.map((service) => ({
        tspName: service.tspName,
        serviceName: service.serviceName,
        serviceTypeIdentifier: service.serviceTypeIdentifier,
        status: service.status,
        certificates: service.certificates.map((base64) =>
          Uint8Array.from(Buffer.from(base64, 'base64'))
        ),
      })),
      fetchedAt: new Date(cached.fetchedAt),
      detail:
        `sequence ${cached.sequenceNumber ?? 'unknown'}, issued ` +
        `${cached.listIssueDateTime ?? 'unknown'}, next update ` +
        `${cached.nextUpdate ?? 'unknown'}, fetched ${cached.fetchedAt}`,
    }
  }
}

/**
 * The instant the cached list stops vouching for itself. An absent or unparseable `NextUpdate`
 * yields zero, so a copy that never declared a validity end can never be counted as fresh.
 */
function validUntil(cached: CachedList): number {
  if (cached.nextUpdate === null) return 0
  const parsed = Date.parse(cached.nextUpdate)
  return Number.isNaN(parsed) ? 0 : parsed
}

// ---------------------------------------------------------------------------
// cache adapters
// ---------------------------------------------------------------------------

/** In-memory cache for a single long-lived process — the default. */
export function memoryTrustCache(): TrustCacheAdapter {
  const store = new Map<string, { value: string; expiresAt: number }>()
  return {
    async get(key) {
      const entry = store.get(key)
      if (entry === undefined) return null
      if (entry.expiresAt <= Date.now()) {
        store.delete(key)
        return null
      }
      return entry.value
    },
    async set(key, value, ttlSeconds) {
      store.set(key, { value, expiresAt: Date.now() + ttlSeconds * 1000 })
    },
  }
}

/**
 * Reuses the session adapter's store for the list cache (`cache: 'session-adapter'`) — on
 * serverless, the session store is the one shared, TTL-capable store that already exists.
 */
export function sessionAdapterTrustCache(session: SessionAdapter): TrustCacheAdapter {
  return {
    async get(key) {
      const record = await session.get(key)
      if (record === null) return null
      const value = record.value
      return typeof value === 'string' ? value : null
    },
    async set(key, value, ttlSeconds) {
      await session.set(key, { value }, ttlSeconds)
    },
  }
}
