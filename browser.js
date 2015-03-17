var Cipher = require('./aead');
exports.aead = Cipher;
exports.createCipher = createCipher;
function createCipher(key, iv) {
  return new Cipher(key, iv);
}
exports.createDecipher = createDecipher;
function createDecipher(key, iv) {
  return new Cipher(key, iv, true);
}

exports.createHmac = require('./polystream');
exports.chacha20 = exports.ChaCha20 = require('./chachastream');
exports.aeadLegacy = exports.AeadLegacy = require('./legacy-aead');