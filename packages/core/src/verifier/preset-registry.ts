/**
 * Per-verifier registry of the preset definitions used by `requests.create`, keyed by
 * `presetRegistryKey`. The session store can carry only JSON, so the `extract` function cannot
 * travel with the request record — the verifier instance keeps the definition and the record
 * keeps the key.
 *
 * Consequence, documented rather than hidden: when a wallet response lands on an instance that
 * never built a request with that preset (fresh serverless instance, rolling deploy), `extract`
 * is skipped and the result carries `claims: null` while `credentials[]` still holds the
 * verified data. Instances that create requests register their presets as a side effect, so in
 * steady state the registry is warm.
 */

import type { PresetDefinition } from '../types.js'

export class PresetRegistry {
  private readonly presets = new Map<string, PresetDefinition<unknown>>()

  register(key: string, preset: PresetDefinition<unknown>): void {
    this.presets.set(key, preset)
  }

  get(key: string): PresetDefinition<unknown> | undefined {
    return this.presets.get(key)
  }
}
