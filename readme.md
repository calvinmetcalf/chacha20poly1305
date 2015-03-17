ChaCha [![Build Status](https://travis-ci.org/calvinmetcalf/chacha20poly1305.svg?branch=master)](https://travis-ci.org/calvinmetcalf/chacha20poly1305)
====


ChaCha20 Poly1305 implementation based on this [repo](https://github.com/devi/chacha20poly1305), test vectors are from this [ietf draft](https://tools.ietf.org/html/draft-irtf-cfrg-chacha20-poly1305-03) and boringssl.  Note there are 2 versions of the chacha20/poly1305 aead, an [earlier draft](https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04) and a modified version with a longer nonce, shorter counter and different tag generation.  This is the more recent version, boringssl implemented the older version which is also included.

By default in node it attempts to use [native bindings](https://github.com/calvinmetcalf/chacha-native) and falls back to using the pure js implimentation. In the browser it defaults to the pure js one.  To use the pure js one in node `require('/chacha/browser');`.

API
===

```js
var chacha = require('chacha');
```

# ChaCha20 Poly1305

```js
var cipher =  chacha.createCipher(key, nonce);
var decipher =  chacha.createDecipher(key, nonce);
```

Create a cipher object by passing it a 256 bit key and 96 bit nonce, API is identical to crypto.createCipheriv()/createDecipheriv in node >= 11 with a gcm mode, in other words, e.g.

```js
cipher.setAAD(nonencrypteddata);// must be called before data
var tag = cipher.getAuthTag();// must be called after finish or end

decipher.setAAD(nonencrypteddata);// must be called before data
decipher.setAuthTag(tag);// must be called before data
```

decipher with throw if you don't set a tag or the tag doesn't match. See the [node docs](https://github.com/joyent/node/blob/cfcb1de130867197cbc9c6012b7e84e08e53d032/doc/api/crypto.markdown#cryptocreatecipherivalgorithm-key-iv) for more info (the iv length for gcm is also 96 bit fyi).

# ChaCha20


```js
var cipher =  chacha.chacha(key, nonce);
```

The API is identical to a cipher/decipher object in node >= 10. Encryption and decryption are the same.

# Poly1305

```js
var hmac =  chacha.createHmac(key);
```

API is identical to an hmac in node, so it's a stream with update and digest methods.

# Legacy Aead

A variant version of the aead that is compatible with boringssl.

```js
var cipher =  new chacha.AeadLegacy(key, nonce);
var decipher =  new chacha.AeadLegacy(key, nonce, true);
```

The third parameter is whether it should decipher, otherwise identical to createCipher/createDecipher. Doesn't implement variable length tags.
