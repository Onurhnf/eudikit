import type { EudikitReactLabels } from '../labels.js'

/** German. */
export const de: EudikitReactLabels = {
  lang: 'de',
  trigger: 'Alter mit Ihrer Wallet bestätigen',
  cancel: 'Abbrechen',
  openWallet: 'Wallet-App auf diesem Gerät öffnen',
  scanQrHint: 'Oder scannen Sie den Code mit der Wallet-App auf Ihrem Telefon.',
  qrLabel: 'QR-Code der Wallet-Anfrage',
  status: {
    idle: '',
    creating: 'Anfrage wird vorbereitet…',
    awaiting_wallet: 'Warten auf Ihre Wallet…',
    polling: 'Warten auf die Antwort Ihrer Wallet…',
    verified: 'Bestätigt.',
    failed: '',
    expired: 'Diese Anfrage ist abgelaufen. Beginnen Sie erneut, wenn Sie bereit sind.',
  },
  errors: {
    USER_DECLINED_OR_NO_CREDENTIAL:
      'Es wurde nichts geteilt. Entweder wurde die Anfrage abgelehnt, oder Ihre Wallet enthält ' +
      'keinen passenden Nachweis.',
    WALLET_UNAVAILABLE:
      'Keine Wallet hat geantwortet. Scannen Sie den QR-Code mit der Wallet-App auf Ihrem Telefon.',
    WALLET_FORMAT_UNSUPPORTED: 'Ihre Wallet kann diesen Nachweis noch nicht vorlegen.',
    WALLET_REJECTED_REQUEST: 'Ihre Wallet hat die Anfrage abgelehnt.',
    UNSUPPORTED_PROTOCOL:
      'Dieser Browser kann nicht direkt mit einer Wallet kommunizieren. Verwenden Sie ' +
      'stattdessen den QR-Code.',
    SESSION_ALREADY_CONSUMED: 'Diese Bestätigung wurde bereits verwendet. Starten Sie eine neue.',
    SESSION_NOT_FOUND: 'Diese Bestätigung ist nicht mehr verfügbar. Starten Sie eine neue.',
    SESSION_EXPIRED: 'Diese Anfrage ist abgelaufen. Beginnen Sie erneut, wenn Sie bereit sind.',
    VERIFICATION_FAILED: 'Der von Ihrer Wallet geteilte Nachweis konnte nicht überprüft werden.',
    generic: 'Die Bestätigung konnte nicht abgeschlossen werden.',
  },
}
