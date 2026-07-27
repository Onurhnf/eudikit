/**
 * `@eudikit/core/next` — Next.js App Router helper.
 *
 * ```ts
 * // app/api/eudikit/[...eudikit]/route.ts
 * export const { GET, POST } = createNextHandler(verifier, {
 *   requests: { age: { preset: presets.age(), channels: ['dc-api', 'qr'] } },
 * })
 * ```
 *
 * A subpath rather than a separate package: one version to keep in step, no cross-package
 * peer-dependency dance. The route file's directory must sit at the verifier's
 * `routeBasePath` (default `/api/eudikit`) — the handler matches full pathnames.
 */

import { createFetchHandler, type FetchHandlerOptions } from '../handler/index.js'
import type { Verifier } from '../types.js'

export function createNextHandler(
  verifier: Verifier,
  options?: FetchHandlerOptions
): {
  GET: (req: Request) => Promise<Response>
  POST: (req: Request) => Promise<Response>
} {
  const handler = createFetchHandler(verifier, options)
  return { GET: handler, POST: handler }
}

export type { FetchHandlerOptions, RegisteredRequest } from '../handler/index.js'
