/**
 * Public type surface of `@eudikit/core`.
 *
 * Two rules govern every declaration here:
 *
 *  - **No dependency type ever leaks into the public API.** Types from `@owf/mdoc`,
 *    `@openid4vc/*`, `dcql` and `jose` are internal; inputs are our own types plus
 *    `Uint8Array`/PEM strings. Even `JsonWebKey` is avoided because it drags in `lib.dom`.
 *  - **Nothing here contains logic.** Types, the error class and its code union only.
 */

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/** Our own JWK type, so that the package never depends on `lib.dom`. */
export interface Jwk {
  kty: string
  kid?: string
  alg?: string
  use?: string
  [param: string]: unknown
}

/**
 * Wallet profile. A *bundle of defaults*, not a lock: it selects request signing, JAR
 * transport, response mode and scheme defaults, each of which can be overridden per request.
 */
export type WalletProfile = 'av' | 'eudi'

export type Channel = 'dc-api' | 'qr' | 'deep-link'

/** The v1 set. Selectable per request. */
export type ClientIdPrefix = 'redirect_uri' | 'x509_san_dns' | 'x509_hash'

export type CredentialFormat = 'mso_mdoc' | 'dc+sd-jwt'

/**
 * A DCQL query — the structural subset of OpenID4VP 1.0 §6 we rely on, expressed as our own
 * type. Unknown properties are tolerated (the spec says implementations MUST ignore them).
 */
export interface DcqlQuery {
  credentials: DcqlCredentialQuery[]
  credential_sets?: Array<{ options: string[][]; required?: boolean }>
  [ext: string]: unknown
}

export interface DcqlCredentialQuery {
  id: string
  format: CredentialFormat
  meta: { doctype_value?: string; vct_values?: string[]; [ext: string]: unknown }
  claims?: Array<{
    id?: string
    path: Array<string | number | null>
    intent_to_retain?: boolean
    [ext: string]: unknown
  }>
  claim_sets?: string[][]
  multiple?: boolean
  [ext: string]: unknown
}

/**
 * A PEM string (`-----BEGIN CERTIFICATE-----…`) or raw DER bytes.
 * No certificate library class is ever accepted or returned.
 */
export type CertificateInput = string | Uint8Array

// ---------------------------------------------------------------------------
// createVerifier(config)
// ---------------------------------------------------------------------------

export interface VerifierConfig {
  /**
   * The https base URL the wallet will reach — required by the QR and deep-link channels.
   * Env fallback: `EUDIKIT_PUBLIC_BASE_URL`.
   *
   * - NOT required for the DC API channel (which works on localhost).
   * - When `requests.create({ channel: 'qr' | 'deep-link' })` runs, a missing or localhost
   *   value throws `CONFIG_PUBLIC_BASE_URL_REQUIRED` with a message describing the tunnel
   *   (cloudflared/ngrok) route, and a plain-http value throws
   *   `CONFIG_PUBLIC_BASE_URL_NOT_HTTPS`.
   */
  publicBaseUrl?: string

  /** Path the handler is mounted at; `request_uri`/`response_uri` derive from it. Default `/api/eudikit`. */
  routeBasePath?: string

  /**
   * Wallet profile — **MANDATORY, no global default.** Because the caller always states the
   * profile, the December 2026 question of "do we change the default and break everyone?"
   * never arises.
   *
   * - `'av'`   → unsigned by-value request, `redirect_uri` prefix, `direct_post` (unencrypted),
   *              scheme `eudi-openid4vp`
   * - `'eudi'` → signed JAR by reference, `direct_post.jwt` (ECDH-ES), `request_uri_method` support
   */
  profile: WalletProfile

  /** Original client id for the `x509_*` prefixes (e.g. a dNSName). Derived automatically for `redirect_uri`. */
  clientId?: string

  /** Default prefix. Per-request override: `requests.create({ clientIdPrefix })`. Default `redirect_uri`. */
  clientIdPrefix?: ClientIdPrefix

  keys?: VerifierKeys

  /** Default: `memorySessionAdapter()` — single instance only; Redis/KV is advised in production. */
  session?: SessionAdapter

  trust?: TrustConfig

  /**
   * Web origins **and** Android app origins — both first class:
   *   `'https://shop.example'`
   *   `'android:apk-key-hash:<base64url-nopad-sha256>'` (list debug and release separately)
   *
   * Used for (a) the `expected_origins` parameter of a signed DC API request and (b) the
   * handover-origin / KB-JWT `aud` check during verification (compared with the `origin:` prefix).
   */
  expectedOrigins?: string[]

  /** TTL of a pending request, in seconds. Default 900. */
  requestTtlSeconds?: number
  /** How long a verification result stays pollable, in seconds. Default 600. */
  resultTtlSeconds?: number

  /**
   * v1.1 RESERVATION — the `org-iso-mdoc` (ISO 18013-7 Annex C + HPKE) adapter plugs in here.
   * No adapter ships in v1; passing a non-empty array throws
   * `CONFIG_UNSUPPORTED_ADAPTER` rather than being silently ignored.
   */
  protocolAdapters?: readonly ProtocolAdapter[]

  /** Test/platform injection. Defaults: `globalThis.fetch` and the real clock. */
  fetch?: typeof fetch
  now?: () => Date
}

export interface VerifierKeys {
  /**
   * Request Object (JAR) signing key — required for `profile: 'eudi'`, `signedRequest: true`,
   * or any `x509_*` prefix. The default `profile: 'av'` flow (unsigned) needs **no key at all**;
   * zero-config demos are a deliberate design goal.
   * Env fallback: `EUDIKIT_SIGNING_KEY` (PKCS#8 PEM).
   *
   * Ephemeral response-encryption keys are deliberately NOT configured here: the SDK generates a
   * fresh pair per request and binds the private half to the session (OpenID4VP 1.0 §14.5).
   */
  requestSigning?: { jwk: Jwk } | { pem: string; alg?: 'ES256' | 'ES384' | 'ES512' }

  /** x5c chain (leaf → root) for `x509_san_dns` / `x509_hash`. */
  requestSigningCertificateChain?: CertificateInput[]
}

export interface TrustConfig {
  /**
   * `'strict'` (default): if any mandatory check fails — trust checks included — `verified` is false.
   * `'permissive'`: **only** `trust.*` checks degrade to warnings (for testbeds and local issuers
   * that are not on the trusted list). Signature, digest, deviceAuth and nonce/audience binding
   * never relax in any mode. `result.policy` reports which mode produced the result, so a
   * permissive result can never masquerade as a strict one.
   */
  mode?: 'strict' | 'permissive'

  /**
   * The AV Trusted List (ETSI TS 119 612 XML) — the layer no TypeScript library provides.
   * `true`/omitted → default URL:
   * `https://acceptance.trust.tech.ec.europa.eu/lists/age-verification/av-tl.xml`
   * (today's only live list; the default changes when a production list is published).
   *
   * Trust model: every `ServiceDigitalIdentity` in the list is a DS certificate → DS-direct-match
   * (byte equality); `additionalTrustAnchors` get PKIX path validation.
   *
   * ⚠️ v1 does **not** verify the list's own XML signature (XAdES); the
   * `trust.list_signature_valid` check reports `'skipped'`.
   */
  avTrustedList?: boolean | { url?: string; refreshIntervalSeconds?: number }

  /** Extra trust anchors (IACA/CA or DS; PEM/DER) — local testbeds and bring-your-own-trust. */
  additionalTrustAnchors?: CertificateInput[]

  /** Trusted-list cache. Default: in-memory; use `'session-adapter'` to reuse the session store on serverless. */
  cache?: 'memory' | 'session-adapter' | TrustCacheAdapter
}

export interface TrustCacheAdapter {
  get(key: string): Promise<string | null>
  set(key: string, value: string, ttlSeconds: number): Promise<void>
}

export interface Verifier {
  requests: {
    create<TClaims = Record<string, unknown>>(
      options: CreateRequestOptions<TClaims>
    ): Promise<CreatedRequest>
  }

  /**
   * Entry point for the DC API channel's response handling (server side). Consumes the session
   * **atomically** — a second call with the same id throws `SESSION_ALREADY_CONSUMED`.
   */
  verify<TClaims = Record<string, unknown>>(
    input: VerifyInput
  ): Promise<VerificationResult<TClaims>>

  /**
   * QR/deep-link: the `direct_post` endpoint (WHATWG Request/Response). Always answers
   * `200` + JSON per OpenID4VP §8.2; consumes the session atomically.
   */
  handleWalletResponse(request: Request): Promise<Response>

  /** QR/deep-link (by reference): the `request_uri` endpoint. Serves the JAR JWT ONCE; 404 afterwards. */
  handleRequestUri(request: Request, sessionId: string): Promise<Response>

  /** Frontend polling — non-destructive; `'expired'` after `resultTtlSeconds`. */
  getResult<TClaims = Record<string, unknown>>(
    sessionId: string,
    options?: { responseCode?: string }
  ): Promise<SessionStatus<TClaims>>

  /**
   * Session-less low-level verification — for testbeds and debugging (the pure-function form of
   * the EU reference implementation's Utility API). The caller supplies nonce/origin binding.
   * Not used in the production flow.
   */
  verifyPresentation(input: {
    format: CredentialFormat
    /** `mso_mdoc`: base64url DeviceResponse; `dc+sd-jwt`: compact SD-JWT+KB string. */
    presentation: string
    bindings: { nonce: string; origin?: string; clientId?: string; responseUri?: string }
    dcql?: DcqlQuery
  }): Promise<VerificationResult>
}

// ---------------------------------------------------------------------------
// Request creation
// ---------------------------------------------------------------------------

export interface CreateRequestOptions<TClaims = Record<string, unknown>> {
  /** `preset` XOR `dcql` — supplying both throws `CONFIG_INVALID`. */
  preset?: PresetDefinition<TClaims>
  dcql?: DcqlQuery

  channel: Channel

  // ---- per-request overrides ----
  profile?: WalletProfile
  clientIdPrefix?: ClientIdPrefix

  /** The SDK generates the nonce (≥16 bytes, base64url). Override only for tests. */
  nonce?: string

  /** Derived from profile + channel by default. */
  signedRequest?: boolean
  /**
   * Response encryption: `dc-api` → `dc_api.jwt`; `qr`/`deep-link` with `'eudi'` → `direct_post.jwt`.
   * The `'av'` profile rejects `true` (Annex A mandates plain `direct_post`), so its default
   * `false` is also the only valid value.
   */
  encryptResponse?: boolean
  /**
   * QR/deep-link JAR transport. Only `'by-value'` is implemented today and it is the default
   * for both channels; requesting `'by-reference'` throws. By-reference transport lands with
   * signed-JAR support — `'eudi'` then defaults to it, as does the `'av'` QR flow (by-value
   * inflates the QR with the whole DCQL).
   */
  jarMode?: 'by-value' | 'by-reference'

  /**
   * Deep-link/QR scheme. Default `'eudi-openid4vp'` — the scheme today's AV wallet builds register
   * on both platforms. The AV profile (Annex A) says `av://` MUST, but that scheme does not appear
   * in the wallets' URL-scheme registrations; to be settled against real devices.
   */
  scheme?: string

  expectedOrigins?: string[]
  ttlSeconds?: number

  /**
   * Same-device return. When given, the `direct_post` response carries a `redirect_uri` with
   * `{RESPONSE_CODE}` substituted; when omitted, the flow is poll-based.
   * e.g. `'https://shop.example/age/done?code={RESPONSE_CODE}'`
   */
  successRedirectTemplate?: string
}

/** Everything the frontend needs, in one object, discriminated by channel. */
export type CreatedRequest =
  | {
      channel: 'dc-api'
      sessionId: string
      /**
       * Goes verbatim into `navigator.credentials.get({ digital: { requests: [dcApiRequest] } })`.
       * Unsigned requests carry no `client_id` (the spec says it MUST be omitted); the audience
       * comes from the origin.
       */
      dcApiRequest: {
        protocol: 'openid4vp-v1-unsigned' | 'openid4vp-v1-signed'
        data: Record<string, unknown>
      }
      expiresAt: Date
    }
  | {
      channel: 'qr'
      sessionId: string
      /** The string to encode into a QR code. Rendering belongs to `@eudikit/react`; core emits no UI. */
      qrPayload: string
      /** Where the JAR is fetched from when `jarMode` is `'by-reference'`. */
      requestUri?: string
      expiresAt: Date
    }
  | {
      channel: 'deep-link'
      sessionId: string
      /** `${scheme}://authorize?client_id=…&request_uri=…`, or all parameters inline when by-value. */
      deepLink: string
      requestUri?: string
      expiresAt: Date
    }

// ---------------------------------------------------------------------------
// Response handling
// ---------------------------------------------------------------------------

export interface VerifyInput {
  sessionId: string
  /** The serialized `DigitalCredential` from the browser: `{ protocol, data }`. */
  response: { protocol: string; data: unknown }
}

// ---------------------------------------------------------------------------
// VerificationResult + the Check taxonomy
// ---------------------------------------------------------------------------

export interface VerificationResult<TClaims = Record<string, unknown>> {
  verified: boolean
  /** The profile the request was created with — which wallet world this was verified against. */
  profile: WalletProfile
  /** Which trust mode produced this result; a permissive result can never look strict. */
  policy: 'strict' | 'permissive'
  /** `null` when `verified` is false. With a preset, the preset's typed claim output. */
  claims: TClaims | null
  credentials: VerifiedCredential[]
  /** The full list in EVERY result, success included. */
  diagnostics: Check[]
  /** The primary reason when `verified` is false; `null` when true. */
  error: EudikitError | null
  sessionId: string
}

export interface VerifiedCredential {
  queryId: string
  format: CredentialFormat
  /** `mso_mdoc` only. */
  docType?: string
  /** `dc+sd-jwt` only. */
  vct?: string
  /**
   * Only requested + mandatory-to-present claims. Keys follow the source format's own
   * convention: the mdoc data element identifier (the namespace is implied by `docType`), or
   * the top-level SD-JWT claim name with nested claims keeping their JSON structure
   * (e.g. `age_equal_or_over: { '18': true }`, `address: { country: 'DE' }`).
   */
  claims: Record<string, unknown>
  issuer: {
    subject: string
    /** AV Trusted List match — informational; the decision lives in the checks. */
    trustedListEntry: {
      tspName: string
      serviceName: string
      status: 'recognized' | 'deprecated' | (string & {})
    } | null
  }
  validity: { validFrom: Date; validUntil: Date; signedAt?: Date }
}

export interface Check {
  id: CheckId
  status: 'passed' | 'failed' | 'skipped'
  /** Human-readable detail. Contains NO claim values (no PII) — safe to log. */
  detail?: string
  /** Which DCQL query id this belongs to (absent for session/trust class checks). */
  credentialId?: string
}

/**
 * A superset of the EU reference verifier's twelve `MsoMdocCheck`s. The difference is not the
 * list, it is the default: there, the report can stand in for the decision (always-accept mode);
 * here the default is REJECT and the report merely informs.
 */
export type CheckId =
  // session / envelope
  | 'session.found'
  | 'session.single_use'
  | 'session.not_expired'
  | 'session.state_match'
  | 'session.response_mode_match'
  | 'session.origin_allowed'
  | 'envelope.jwe_decrypted'
  | 'envelope.key_binding'
  // DCQL post-validation — cannot be disabled
  | 'dcql.credential_sets_satisfied'
  | 'dcql.doctype_match'
  | 'dcql.vct_match'
  | 'dcql.claims_present'
  | 'dcql.claim_types_valid'
  // mdoc
  | 'mdoc.decoded'
  | 'mdoc.response_status_ok'
  | 'mdoc.issuer_auth_present'
  | 'mdoc.issuer_chain_parsed'
  | 'mdoc.issuer_signature_valid'
  | 'mdoc.issuer_key_algorithm_allowed'
  | 'mdoc.validity_window'
  | 'mdoc.doctype_consistent'
  | 'mdoc.value_digests_valid'
  | 'mdoc.device_signed_present'
  | 'mdoc.device_key_authorized'
  | 'mdoc.device_key_matches_mso'
  | 'mdoc.device_signature_valid'
  | 'mdoc.status_list_valid'
  // SD-JWT VC
  | 'sdjwt.decoded'
  | 'sdjwt.issuer_signature_valid'
  | 'sdjwt.disclosures_valid'
  | 'sdjwt.kb_present'
  | 'sdjwt.kb_nonce_match'
  | 'sdjwt.kb_aud_match'
  | 'sdjwt.kb_sd_hash_valid'
  | 'sdjwt.validity_window'
  | 'sdjwt.status_list_valid'
  // trust
  | 'trust.list_fresh'
  | 'trust.list_signature_valid'
  | 'trust.issuer_in_trusted_list'
  | 'trust.chain_valid'

export type SessionStatus<TClaims = Record<string, unknown>> =
  | { status: 'pending' }
  | { status: 'verified'; result: VerificationResult<TClaims> }
  | { status: 'failed'; result: VerificationResult<TClaims> }
  | { status: 'expired' }

// ---------------------------------------------------------------------------
// Error model
// ---------------------------------------------------------------------------

export type EudikitErrorCategory = 'config' | 'session' | 'wallet' | 'verification' | 'internal'

export type EudikitErrorCode =
  // config — thrown while building a request (fail loud)
  | 'CONFIG_PUBLIC_BASE_URL_REQUIRED'
  | 'CONFIG_PUBLIC_BASE_URL_NOT_HTTPS'
  | 'CONFIG_SIGNING_KEY_REQUIRED'
  | 'CONFIG_INVALID'
  | 'CONFIG_UNSUPPORTED_ADAPTER'
  | 'CHANNEL_PROFILE_MISMATCH'
  // session
  | 'SESSION_NOT_FOUND'
  | 'SESSION_EXPIRED'
  | 'SESSION_ALREADY_CONSUMED'
  | 'SESSION_STATE_MISMATCH'
  | 'RESPONSE_CODE_MISMATCH'
  // wallet
  | 'USER_DECLINED_OR_NO_CREDENTIAL'
  | 'WALLET_REJECTED_REQUEST'
  | 'WALLET_FORMAT_UNSUPPORTED'
  | 'WALLET_UNAVAILABLE'
  | 'UNSUPPORTED_PROTOCOL'
  // verification — verify() does not throw these; they come back as result.error
  | 'VERIFICATION_FAILED'
  | 'ENVELOPE_DECRYPTION_FAILED'
  | 'PRESENTATION_MALFORMED'
  // internal
  | 'TRUSTED_LIST_UNAVAILABLE'
  | 'INTERNAL'

/**
 * Which category each error code belongs to. Kept as data rather than a constructor argument so
 * that code and category can never disagree.
 */
const ERROR_CATEGORY: Record<EudikitErrorCode, EudikitErrorCategory> = {
  CONFIG_PUBLIC_BASE_URL_REQUIRED: 'config',
  CONFIG_PUBLIC_BASE_URL_NOT_HTTPS: 'config',
  CONFIG_SIGNING_KEY_REQUIRED: 'config',
  CONFIG_INVALID: 'config',
  CONFIG_UNSUPPORTED_ADAPTER: 'config',
  CHANNEL_PROFILE_MISMATCH: 'config',
  SESSION_NOT_FOUND: 'session',
  SESSION_EXPIRED: 'session',
  SESSION_ALREADY_CONSUMED: 'session',
  SESSION_STATE_MISMATCH: 'session',
  RESPONSE_CODE_MISMATCH: 'session',
  USER_DECLINED_OR_NO_CREDENTIAL: 'wallet',
  WALLET_REJECTED_REQUEST: 'wallet',
  WALLET_FORMAT_UNSUPPORTED: 'wallet',
  WALLET_UNAVAILABLE: 'wallet',
  UNSUPPORTED_PROTOCOL: 'wallet',
  VERIFICATION_FAILED: 'verification',
  ENVELOPE_DECRYPTION_FAILED: 'verification',
  PRESENTATION_MALFORMED: 'verification',
  TRUSTED_LIST_UNAVAILABLE: 'internal',
  INTERNAL: 'internal',
}

/**
 * The single error class. Lower-layer errors never escape through it: the underlying failure
 * stays in `cause`, and the public surface is always a stable `code` + `category`.
 *
 * `USER_DECLINED_OR_NO_CREDENTIAL` is **deliberately combined**: the spec collapses "no matching
 * credential", "user did not consent" and "wallet could not authenticate the user" into a single
 * `access_denied`, and the DC API actively encourages wallets to stay silent. Any API claiming to
 * tell those three apart is lying, so this one documents the merge instead.
 */
export class EudikitError extends Error {
  readonly code: EudikitErrorCode
  readonly category: EudikitErrorCategory
  /** The raw OID4VP error code the wallet sent, when there was one. Informational only. */
  readonly walletError?: string

  constructor(
    code: EudikitErrorCode,
    message: string,
    options?: { walletError?: string; cause?: unknown }
  ) {
    super(message, options?.cause !== undefined ? { cause: options.cause } : undefined)
    this.name = 'EudikitError'
    this.code = code
    this.category = ERROR_CATEGORY[code]
    if (options?.walletError !== undefined) this.walletError = options.walletError
  }
}

// ---------------------------------------------------------------------------
// SessionAdapter
// ---------------------------------------------------------------------------

/**
 * The Auth.js pattern: the adapter is a dumb atomic KV store, the state machine lives in core.
 * Every phase (pending request → JAR served → response received → result) has its own key, and
 * every transition is an atomic `consume` + `set`.
 */
export interface SessionAdapter {
  set(key: string, record: StoredRecord, ttlSeconds: number): Promise<void>
  /**
   * ATOMIC read-and-delete (Redis `GETDEL` semantics) — the heart of single-use nonce/state
   * consumption. Of two concurrent `consume` calls for the same key, exactly one must win.
   */
  consume(key: string): Promise<StoredRecord | null>
  /** Non-destructive read — for result polling and the trusted-list cache. */
  get(key: string): Promise<StoredRecord | null>
  delete(key: string): Promise<void>
}

/** JSON-serializable. Its inner shape is versioned and is NOT a public contract. */
export type StoredRecord = Record<string, unknown>

/** Structural type — no Redis library type is ever imported. */
export interface RedisLikeClient {
  get(key: string): Promise<string | null>
  set(key: string, value: string, opts?: { EX?: number }): Promise<unknown>
  /** Used when present; otherwise a Lua/MULTI equivalent is used. */
  getdel?(key: string): Promise<string | null>
  del(key: string): Promise<unknown>
  eval?(script: string, keys: string[], args: string[]): Promise<unknown>
}

export interface KvLikeClient {
  get(key: string): Promise<string | null>
  put(key: string, value: string, opts?: { expirationTtl?: number }): Promise<unknown>
  delete(key: string): Promise<unknown>
}

// ---------------------------------------------------------------------------
// Presets
// ---------------------------------------------------------------------------

export interface PresetDefinition<TClaims = Record<string, unknown>> {
  readonly id: string
  readonly dcql: DcqlQuery
  /** Produces typed claims from verified credentials; core calls this inside `verify()`. */
  readonly extract: (credentials: VerifiedCredential[]) => TClaims
}

export interface AgeClaims {
  /** Whether the requested threshold is met — computed SERVER-SIDE; wallet value-matching is never trusted. */
  ageOver: boolean
  threshold: number
  /** Which credential path satisfied it — honest diagnostics. `'mdl'` only occurs with `includeMdl`. */
  source: 'av-attestation' | 'pid-mdoc' | 'pid-sdjwt' | 'mdl' | 'birth-date'
}

export interface AgeOptions {
  /**
   * Default 18. Thresholds known to the AV attestation: 13, 15, 16, 18, 21, 23, 25, 27, 28, 40,
   * 60, 65, 67. The threshold is deliberately configurable rather than fixed at 18.
   */
  threshold?: number
  /**
   * Domestic PID doctypes/vcts (e.g. `eu.europa.ec.eudi.pid.de.1` / `urn:eudi:pid:de:1`).
   * The German defaults are CLAIMED, not verified — override them for your market.
   */
  domesticPids?: Array<{ format: CredentialFormat; id: string }>
  /**
   * Last resort: request `birth_date` and compute the age SERVER-SIDE. Default false (data
   * minimization). Even when enabled, the raw birth date is NEVER placed in `claims` — only the
   * derived boolean plus `source: 'birth-date'`.
   */
  allowBirthDateFallback?: boolean
  /** Add the US-style mDL option (`org.iso.18013.5.1`). Default false (EU focus). */
  includeMdl?: boolean
}

export interface CountryClaims {
  attribute: 'nationality' | 'residence'
  /**
   * A set of ISO 3166-1 alpha-2 codes. In mdoc, nationality is always an array (even for a single
   * nationality), so the business rule must be written as "set ∩ allowed countries", never
   * "nationality == X". The reserved codes `QU` (unknown) and `QS` (stateless) are passed through
   * unchanged rather than silently producing a false negative.
   */
  countries: string[]
}

export interface CountryOptions {
  /**
   * MANDATORY, no default: nationality and residence are different business rules — iGaming
   * licence geography needs residence, content restrictions need nationality. A silent default
   * would produce the wrong legal outcome.
   */
  attribute: 'nationality' | 'residence'
}

// ---------------------------------------------------------------------------
// Extension point — ProtocolAdapter (v1.1 reservation)
// ---------------------------------------------------------------------------

/**
 * v1.1 RESERVATION — no implementation, no adapter ships. First concrete candidate:
 * `@eudikit/iso-18013-7` → `org-iso-mdoc` (ISO 18013-7 Annex C): CBOR DeviceRequest +
 * EncryptionInfo generation, HPKE (RFC 9180) response decryption, the `'dcapi'` SessionTranscript.
 */
export interface ProtocolAdapter {
  /** The DC API protocol name — e.g. `'org-iso-mdoc'`. */
  readonly protocol: string
  /** Builds the protocol-specific `{ protocol, data }` for `requests.create({ channel: 'dc-api' })`. */
  buildDcApiRequest(input: {
    dcql: DcqlQuery
    nonce: string
    session: Readonly<StoredRecord>
  }): Promise<{ protocol: string; data: Record<string, unknown> }>
  /** Decodes a protocol-specific response for `verify()` and contributes to the check list. */
  verifyDcApiResponse(input: {
    data: unknown
    session: Readonly<StoredRecord>
    expectedOrigins: string[]
  }): Promise<{ credentials: VerifiedCredential[]; checks: Check[] }>
}
