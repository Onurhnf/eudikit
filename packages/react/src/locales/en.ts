import type { EudikitReactLabels } from '../labels.js'

/** English — the catalog every resolution falls back to. */
export const en: EudikitReactLabels = {
  lang: 'en',
  trigger: 'Verify your age with your wallet',
  cancel: 'Cancel',
  openWallet: 'Open your wallet app on this device',
  scanQrHint: 'Or scan the code with the wallet app on your phone.',
  qrLabel: 'Wallet request QR code',
  status: {
    idle: '',
    creating: 'Preparing the request…',
    awaiting_wallet: 'Waiting for your wallet…',
    polling: 'Waiting for your wallet to answer…',
    verified: 'Verified.',
    failed: '',
    expired: 'This request expired. Start again when you are ready.',
  },
  errors: {
    USER_DECLINED_OR_NO_CREDENTIAL:
      'Nothing was shared. Either the request was declined, or your wallet holds no credential ' +
      'that answers it.',
    WALLET_UNAVAILABLE: 'No wallet answered. Scan the QR code with the wallet app on your phone.',
    WALLET_FORMAT_UNSUPPORTED: 'Your wallet cannot present this credential yet.',
    WALLET_REJECTED_REQUEST: 'Your wallet rejected the request.',
    UNSUPPORTED_PROTOCOL: 'This browser cannot talk to a wallet directly. Use the QR code instead.',
    SESSION_ALREADY_CONSUMED: 'That verification was already used. Start a new one.',
    SESSION_NOT_FOUND: 'That verification is no longer available. Start a new one.',
    SESSION_EXPIRED: 'This request expired. Start again when you are ready.',
    VERIFICATION_FAILED: 'The credential your wallet shared could not be verified.',
    generic: 'Verification could not be completed.',
  },
}
