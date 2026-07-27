/**
 * The built-in label catalogs, one per `Locale`:
 *
 * ```ts
 * import { de } from '@eudikit/react/locales'
 *
 * <AgeGate labels={de} … />   // same catalog that locale="de" resolves
 * ```
 *
 * Plain data with no `'use client'` directive, so a server component can pick a catalog —
 * from its own language negotiation — and pass it down as a prop.
 */

export { de } from './de.js'
export { en } from './en.js'
export { tr } from './tr.js'
