import { EudikitError } from '../types.js'

/**
 * Every public entry point that is still a skeleton routes through here, so that "not built yet"
 * is loud, uniform and greppable — never a silently wrong result.
 */
export function notImplemented(surface: string): never {
  throw new EudikitError(
    'INTERNAL',
    `${surface} is not implemented yet — @eudikit/core is a pre-release skeleton. ` +
      'The public surface is stable; the engine behind it is being built.'
  )
}
