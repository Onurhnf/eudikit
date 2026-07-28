import type { EudikitReactLabels } from '../labels.js'

/** Turkish. */
export const tr: EudikitReactLabels = {
  lang: 'tr',
  trigger: 'Yaşınızı cüzdanınızla doğrulayın',
  cancel: 'İptal',
  openWallet: 'Cüzdan uygulamanızı bu cihazda açın',
  scanQrHint: 'Ya da kodu telefonunuzdaki cüzdan uygulamasıyla okutun.',
  qrLabel: 'Cüzdan isteği QR kodu',
  status: {
    idle: '',
    creating: 'İstek hazırlanıyor…',
    awaiting_wallet: 'Cüzdanınız bekleniyor…',
    polling: 'Cüzdanınızın yanıtı bekleniyor…',
    verified: 'Doğrulandı.',
    failed: '',
    expired: 'Bu isteğin süresi doldu. Hazır olduğunuzda yeniden başlayın.',
  },
  declined: 'Cüzdanınızın yanıtı bu sayfanın gereğini karşılamıyor.',
  errors: {
    USER_DECLINED_OR_NO_CREDENTIAL:
      'Hiçbir şey paylaşılmadı. İstek ya reddedildi ya da cüzdanınızda bu isteği karşılayan ' +
      'bir kimlik yok.',
    WALLET_UNAVAILABLE:
      'Hiçbir cüzdan yanıt vermedi. QR kodu telefonunuzdaki cüzdan uygulamasıyla okutun.',
    WALLET_FORMAT_UNSUPPORTED: 'Cüzdanınız bu kimliği henüz sunamıyor.',
    WALLET_REJECTED_REQUEST: 'Cüzdanınız isteği reddetti.',
    UNSUPPORTED_PROTOCOL:
      'Bu tarayıcı bir cüzdanla doğrudan iletişim kuramıyor. Bunun yerine QR kodunu kullanın.',
    SESSION_ALREADY_CONSUMED: 'Bu doğrulama daha önce kullanılmış. Yenisini başlatın.',
    SESSION_NOT_FOUND: 'Bu doğrulama artık geçerli değil. Yenisini başlatın.',
    SESSION_EXPIRED: 'Bu isteğin süresi doldu. Hazır olduğunuzda yeniden başlayın.',
    VERIFICATION_FAILED: 'Cüzdanınızın paylaştığı kimlik doğrulanamadı.',
    generic: 'Doğrulama tamamlanamadı.',
  },
}
