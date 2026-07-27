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
 * peer-dependency dance.
 *
 * STATUS: skeleton — see `src/index.ts`.
 */

import type { FetchHandlerOptions } from '../handler/index.js'
import { notImplemented } from '../internal/not-implemented.js'
import type { Verifier } from '../types.js'

export function createNextHandler(
  _verifier: Verifier,
  _options?: FetchHandlerOptions
): {
  GET: (req: Request) => Promise<Response>
  POST: (req: Request) => Promise<Response>
} {
  return notImplemented('createNextHandler()')
}

export type { FetchHandlerOptions } from '../handler/index.js'
