/**
 * Parser for an ETSI TS 119 612 trusted list — the XML format of the EU Age Verification
 * trusted list (and, later, of the eIDAS lists of trusted lists).
 *
 * Deliberately a *reader*, not a validator: it extracts scheme metadata and the current
 * service entries (TSP name, service name, type, status, and the DER certificates of
 * `ServiceDigitalIdentity`) and ignores everything else. `ServiceHistoryInstance` elements are
 * skipped on purpose — they describe *prior* statuses, and treating a historical identity as a
 * current one would resurrect certificates the scheme operator has rotated out.
 *
 * XML handling runs on `@xmldom/xmldom`: a dependency-free, pure-JavaScript DOM with proper
 * namespace support, which is exactly what this document needs (its elements live in the ETSI
 * namespace and real-world lists are free to choose prefixes). Traversal below is
 * namespace-checked at every step rather than matching tag strings.
 */

import { DOMParser, onErrorStopParsing } from '@xmldom/xmldom'

export const ETSI_TSL_NAMESPACE = 'http://uri.etsi.org/02231/v2#'

export interface TrustedListService {
  tspName: string
  serviceName: string
  /** e.g. `http://trust.tech.ec.europa.eu/lists/age-verification/service-type/paa` */
  serviceTypeIdentifier: string
  /**
   * Last path segment of the `ServiceStatus` URI — `'recognized'` and `'deprecated'` on the AV
   * list. Unknown values pass through verbatim; the trust decision treats anything that is not
   * `recognized` as not trusted, so a new status can never silently widen trust.
   */
  status: string
  /** DER certificates of `ServiceDigitalIdentity/DigitalId/X509Certificate`. May be empty. */
  certificates: Uint8Array[]
}

export interface TrustedListDocument {
  sequenceNumber: number | null
  listIssueDateTime: string | null
  nextUpdate: string | null
  services: TrustedListService[]
}

/**
 * Parses a trusted-list XML document. Throws a plain `Error` on anything that is not a
 * well-formed TS 119 612 list — the caller (the trusted-list source) treats a parse failure
 * exactly like a fetch failure, so a corrupted download can never replace a good cached list.
 */
export function parseTrustedListXml(xml: string): TrustedListDocument {
  const document = new DOMParser({ onError: onErrorStopParsing }).parseFromString(
    xml,
    'application/xml'
  )

  const root = document.documentElement
  if (
    root === null ||
    root.namespaceURI !== ETSI_TSL_NAMESPACE ||
    root.localName !== 'TrustServiceStatusList'
  ) {
    throw new Error(
      'not an ETSI TS 119 612 trusted list: expected a TrustServiceStatusList root element in ' +
        `the "${ETSI_TSL_NAMESPACE}" namespace`
    )
  }

  const schemeInformation = firstChild(root, 'SchemeInformation')
  const sequenceRaw = textOf(childOrNull(schemeInformation, 'TSLSequenceNumber'))
  const nextUpdateElement = childOrNull(schemeInformation, 'NextUpdate')

  const services: TrustedListService[] = []
  const providerList = childOrNull(root, 'TrustServiceProviderList')
  for (const provider of children(providerList, 'TrustServiceProvider')) {
    const tspInformation = childOrNull(provider, 'TSPInformation')
    const tspName = localizedName(childOrNull(tspInformation, 'TSPName'))
    const tspServices = childOrNull(provider, 'TSPServices')
    for (const service of children(tspServices, 'TSPService')) {
      // ServiceInformation only: ServiceHistory carries superseded statuses and identities.
      const information = childOrNull(service, 'ServiceInformation')
      if (information === null) continue
      services.push({
        tspName,
        serviceName: localizedName(childOrNull(information, 'ServiceName')),
        serviceTypeIdentifier: textOf(childOrNull(information, 'ServiceTypeIdentifier')),
        status: lastUriSegment(textOf(childOrNull(information, 'ServiceStatus'))),
        certificates: serviceCertificates(childOrNull(information, 'ServiceDigitalIdentity')),
      })
    }
  }

  return {
    sequenceNumber: sequenceRaw === '' ? null : Number.parseInt(sequenceRaw, 10),
    listIssueDateTime: emptyToNull(textOf(childOrNull(schemeInformation, 'ListIssueDateTime'))),
    nextUpdate: emptyToNull(textOf(childOrNull(nextUpdateElement, 'dateTime'))),
    services,
  }
}

// ---------------------------------------------------------------------------
// namespace-checked traversal
// ---------------------------------------------------------------------------

/** Minimal structural view of a DOM element — keeps xmldom types out of every signature. */
interface XmlElement {
  readonly namespaceURI: string | null
  readonly localName: string | null
  readonly childNodes: { readonly length: number; item(index: number): XmlNode | null }
  readonly nodeType: number
  getAttribute(name: string): string | null
}

interface XmlNode {
  readonly nodeType: number
  readonly nodeValue: string | null
}

const ELEMENT_NODE = 1
const TEXT_NODE = 3
const CDATA_SECTION_NODE = 4

function* children(parent: XmlElement | null, localName: string): Generator<XmlElement> {
  if (parent === null) return
  for (let i = 0; i < parent.childNodes.length; i++) {
    const node = parent.childNodes.item(i)
    if (node === null || node.nodeType !== ELEMENT_NODE) continue
    const element = node as unknown as XmlElement
    if (element.namespaceURI === ETSI_TSL_NAMESPACE && element.localName === localName) {
      yield element
    }
  }
}

function childOrNull(parent: XmlElement | null, localName: string): XmlElement | null {
  for (const element of children(parent, localName)) return element
  return null
}

function firstChild(parent: XmlElement, localName: string): XmlElement {
  const element = childOrNull(parent, localName)
  if (element === null) {
    throw new Error(`trusted list is missing its ${localName} element`)
  }
  return element
}

function textOf(element: XmlElement | null): string {
  if (element === null) return ''
  let text = ''
  for (let i = 0; i < element.childNodes.length; i++) {
    const node = element.childNodes.item(i)
    if (node !== null && (node.nodeType === TEXT_NODE || node.nodeType === CDATA_SECTION_NODE)) {
      text += node.nodeValue ?? ''
    }
  }
  return text.trim()
}

/** Reads a `<Name xml:lang="…">` list, preferring English, falling back to the first entry. */
function localizedName(container: XmlElement | null): string {
  let first = ''
  for (const name of children(container, 'Name')) {
    const value = textOf(name)
    if (value === '') continue
    if (first === '') first = value
    if (name.getAttribute('xml:lang')?.toLowerCase().startsWith('en')) return value
  }
  return first
}

function serviceCertificates(identity: XmlElement | null): Uint8Array[] {
  const certificates: Uint8Array[] = []
  for (const digitalId of children(identity, 'DigitalId')) {
    for (const certificate of children(digitalId, 'X509Certificate')) {
      const base64 = textOf(certificate).replace(/\s+/g, '')
      if (base64 === '') continue
      const der = Uint8Array.from(Buffer.from(base64, 'base64'))
      if (der.length === 0) {
        throw new Error('trusted list carries an X509Certificate that is not valid base64')
      }
      certificates.push(der)
    }
  }
  return certificates
}

function lastUriSegment(uri: string): string {
  const index = uri.lastIndexOf('/')
  return index === -1 ? uri : uri.slice(index + 1)
}

function emptyToNull(value: string): string | null {
  return value === '' ? null : value
}
