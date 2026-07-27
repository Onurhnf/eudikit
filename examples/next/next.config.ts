import type { NextConfig } from 'next'

const config: NextConfig = {
  // The workspace packages ship compiled ESM; nothing here needs transpiling by Next.
  reactStrictMode: true,
  experimental: {
    // The repository is on TypeScript 7, whose compiler API Next cannot drive in-process; this
    // makes the build shell out to the TypeScript CLI instead.
    useTypeScriptCli: true,
  },
}

export default config
