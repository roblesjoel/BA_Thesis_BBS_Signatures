const crypto = window && (window.crypto || window.msCrypto)

export function randomBytes (bytesLength = 32) {
  return crypto.getRandomValues(new Uint8Array(bytesLength))
}
