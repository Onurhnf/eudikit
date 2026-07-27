/**
 * Test doubles for the two browser surfaces this package talks to: the eudikit handler over
 * `fetch`, and the Digital Credentials API. Both are scripted per test rather than mocked at
 * the module boundary, so what runs in the tests is the real hook against the real HTTP shapes
 * the core handler produces.
 */

import type { ReactElement } from 'react'
import { vi } from 'vitest'
import type { UseVerificationResult } from '../src/use-verification.js'
import { type UseVerificationOptions, useVerification } from '../src/use-verification.js'

export const ENDPOINT = '/api/eudikit'

// ---------------------------------------------------------------------------
// handler stub
// ---------------------------------------------------------------------------

export interface FetchCall {
  method: string
  url: string
  body: Record<string, unknown> | null
}

export type RouteHandler = (call: FetchCall) => unknown

/**
 * Installs a `fetch` that logs every call and delegates to `route`. A returned object becomes a
 * 200 JSON body, a returned `Response` is served as-is, and a thrown value propagates — which
 * is how a transport failure looks to the client.
 */
export function installFetch(route: RouteHandler): { calls: FetchCall[] } {
  const calls: FetchCall[] = []
  const impl = async (input: unknown, init?: RequestInit): Promise<Response> => {
    const url = String(input)
    const rawBody = init?.body
    calls.push({
      method: init?.method ?? 'GET',
      url,
      body: typeof rawBody === 'string' ? (JSON.parse(rawBody) as Record<string, unknown>) : null,
    })
    const outcome = await route(calls[calls.length - 1] as FetchCall)
    if (outcome instanceof Response) return outcome
    return new Response(JSON.stringify(outcome), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    })
  }
  vi.stubGlobal('fetch', vi.fn(impl))
  return { calls }
}

export function jsonError(status: number, code: string): Response {
  return new Response(JSON.stringify({ error: code }), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

export function createdQr(overrides: { sessionId?: string; ttlMs?: number } = {}): unknown {
  return {
    channel: 'qr',
    sessionId: overrides.sessionId ?? 'session-qr',
    qrPayload: 'eudi-openid4vp://authorize?client_id=redirect_uri%3Ahttps%3A%2F%2Frp.example',
    expiresAt: new Date(Date.now() + (overrides.ttlMs ?? 900_000)).toISOString(),
  }
}

export function createdDcApi(protocol = 'openid4vp-v1-unsigned'): unknown {
  return {
    channel: 'dc-api',
    sessionId: 'session-dc',
    dcApiRequest: {
      protocol,
      data: { response_type: 'vp_token', response_mode: 'dc_api', nonce: 'n0nce' },
    },
    expiresAt: new Date(Date.now() + 900_000).toISOString(),
  }
}

export const VERIFIED_BODY = {
  status: 'verified',
  verified: true,
  claims: { ageOver: true, threshold: 18, source: 'av-attestation' },
}

// ---------------------------------------------------------------------------
// Digital Credentials API stub
// ---------------------------------------------------------------------------

export interface DcApiStub {
  get: ReturnType<typeof vi.fn>
}

export function installDigitalCredentials(options?: {
  allows?: (protocol: string) => boolean
  get?: () => Promise<unknown>
}): DcApiStub {
  const constructorStub = function DigitalCredential(): void {
    // The spec exposes a constructor; only its static protocol check is used here.
  }
  Object.assign(constructorStub, {
    userAgentAllowsProtocol: (protocol: string) => options?.allows?.(protocol) ?? true,
  })
  vi.stubGlobal('DigitalCredential', constructorStub)

  const get = vi.fn(
    options?.get ??
      (async () => ({ protocol: 'openid4vp-v1-unsigned', data: { vp_token: { age: ['ey'] } } }))
  )
  Object.defineProperty(navigator, 'credentials', {
    value: { get },
    configurable: true,
    writable: true,
  })
  return { get }
}

export function removeDigitalCredentials(): void {
  if ('credentials' in navigator) {
    Reflect.deleteProperty(navigator, 'credentials')
  }
}

export function domError(name: string): Error {
  const error = new Error(name)
  error.name = name
  return error
}

export function setVisibility(state: 'visible' | 'hidden'): void {
  Object.defineProperty(document, 'visibilityState', { value: state, configurable: true })
  document.dispatchEvent(new Event('visibilitychange'))
}

// ---------------------------------------------------------------------------
// hook harness
// ---------------------------------------------------------------------------

let current: UseVerificationResult | null = null

export function hook(): UseVerificationResult {
  if (current === null) throw new Error('the harness is not mounted')
  return current
}

export function resetHarness(): void {
  current = null
}

export function Harness(props: { options: UseVerificationOptions }): ReactElement {
  const verification = useVerification(props.options)
  current = verification
  return (
    <output>
      {verification.status}
      {verification.qrPayload !== null ? (
        <span data-testid="qr">{verification.qrPayload}</span>
      ) : null}
    </output>
  )
}
