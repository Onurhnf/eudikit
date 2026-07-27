/**
 * Synthetic ETSI TS 119 612 documents for the trusted-list tests: the real downloaded list
 * (test/fixtures/av-tl.xml) exercises the parser against production shapes, while these
 * builders produce small lists containing *our* fixture DS certificates so the byte-equality
 * matching can be driven through every status.
 */

export interface SyntheticService {
  tspName: string
  serviceName: string
  status: 'recognized' | 'deprecated' | string
  certificates: Uint8Array[]
}

const STATUS_BASE = 'http://trust.tech.ec.europa.eu/lists/age-verification/service-status'
const SERVICE_TYPE = 'http://trust.tech.ec.europa.eu/lists/age-verification/service-type/paa'

export interface SyntheticListOptions {
  /** The list's own validity statement — the freshness rule for cached copies. */
  nextUpdate?: string
}

export function buildTrustedListXml(
  services: SyntheticService[],
  options: SyntheticListOptions = {}
): string {
  const providers = services
    .map(
      (service) => `
    <TrustServiceProvider>
      <TSPInformation>
        <TSPName><Name xml:lang="en">${service.tspName}</Name></TSPName>
      </TSPInformation>
      <TSPServices>
        <TSPService>
          <ServiceInformation>
            <ServiceTypeIdentifier>${SERVICE_TYPE}</ServiceTypeIdentifier>
            <ServiceName><Name xml:lang="en">${service.serviceName}</Name></ServiceName>
            <ServiceDigitalIdentity>
              ${service.certificates
                .map(
                  (der) =>
                    `<DigitalId><X509Certificate>${Buffer.from(der).toString('base64')}</X509Certificate></DigitalId>`
                )
                .join('\n              ')}
            </ServiceDigitalIdentity>
            <ServiceStatus>${STATUS_BASE}/${service.status}</ServiceStatus>
            <StatusStartingTime>2026-01-01T00:00:00Z</StatusStartingTime>
          </ServiceInformation>
        </TSPService>
      </TSPServices>
    </TrustServiceProvider>`
    )
    .join('\n')

  return `<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" TSLTag="http://uri.etsi.org/19612/TSLTag">
  <SchemeInformation>
    <TSLVersionIdentifier>6</TSLVersionIdentifier>
    <TSLSequenceNumber>1</TSLSequenceNumber>
    <ListIssueDateTime>2026-07-01T00:00:00Z</ListIssueDateTime>
    <NextUpdate><dateTime>${options.nextUpdate ?? '2026-12-31T00:00:00Z'}</dateTime></NextUpdate>
  </SchemeInformation>
  <TrustServiceProviderList>${providers}
  </TrustServiceProviderList>
</TrustServiceStatusList>`
}

/** A fetch stub serving canned bodies per call, then failing once the script runs out. */
export function scriptedFetch(script: Array<string | Error>): {
  fetch: typeof fetch
  calls: () => number
} {
  let index = 0
  const impl = async (): Promise<Response> => {
    const step = script[index] ?? new Error('scripted fetch exhausted')
    index += 1
    if (step instanceof Error) throw step
    return new Response(step, { status: 200, headers: { 'content-type': 'application/xml' } })
  }
  return { fetch: impl as unknown as typeof fetch, calls: () => index }
}
