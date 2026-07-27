import { presets } from '@eudikit/core'
import { createNextHandler } from '@eudikit/core/next'
import { verifier } from '@/lib/verifier'

/**
 * Every eudikit route, mounted at `/api/eudikit` — the path the verifier derives its
 * `response_uri` and `request_uri` from, so the directory has to match `routeBasePath`.
 *
 * The registry is the whole client-facing surface: the browser asks for `age` by name and can
 * never send a DCQL query of its own. Channels are restricted to the two the AV wallet answers;
 * `dc-api` is left out because that wallet does not speak `openid4vp-v1-*` over the Digital
 * Credentials API.
 */
export const { GET, POST } = createNextHandler(verifier, {
  requests: {
    age: {
      preset: presets.age({ threshold: 18 }),
      channels: ['qr', 'deep-link'],
    },
  },
})

// Node APIs (crypto, the mdoc chain) and a per-request session store: never prerendered.
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'
