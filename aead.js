var inherits = require('inherits');
var CipherBase = require('./cipherbase');
var Chacha20 = require('./chacha20');
var CipherBase = require('./cipherbase');
var Poly1305 = require('./poly1305');
inherits(Cipher, CipherBase);
module.exports = Cipher;
function Cipher(key, iv, decrypt){
  if (!(this instanceof Cipher)) {
    return new Cipher(key, iv, decrypt);
  }
  CipherBase.call(this);
  this.alen = 0;
  this.clen = 0;
  this.chacha = new Chacha20(key, iv);
  this.poly = new Poly1305(this.chacha.getBytes(64));
  this.tag = null;
  this._decrypt = decrypt;
  this._hasData = false;
}
Cipher.prototype.setAAD = function (aad) {
  if (this._hasData) {
    throw new Error('Attempting to set AAD in unsupported state');
  }
  this.alen = aad.length;
  this.poly.update(aad);
  var padding = new Buffer(padAmount(this.alen));
  if (padding.length) {
    padding.fill(0);
    this.poly.update(padding);
  }
};
Cipher.prototype._update = function (chunk) {
  if (!this._hasData) {
    this._hasData = true;
  }
  var len = chunk.length;
  if (!len) {
    return next();
  }
  this.clen += len;
  var pad = this.chacha.getBytes(len);
  var i = -1;
  while (++i < len) {
    pad[i] ^= chunk[i];
  }
  if (this._decrypt) {
    this.poly.update(chunk);
  } else {
    this.poly.update(pad);
  }
  return pad;
};
Cipher.prototype._final = function () {
  if (this._decrypt && !this.tag) {
    throw new Error('Unsupported state or unable to authenticate data');
  }
  var padding = new Buffer(padAmount(this.clen));
  if (padding.length) {
    padding.fill(0);
    this.poly.update(padding);
  }
  var lens = new Buffer(16);
  lens.fill(0);
  lens.writeUInt32LE(this.alen, 0);
  lens.writeUInt32LE(this.clen, 8);
  var tag = this.poly.update(lens).finish();
  if (this._decrypt) {
    if (xorTest(tag, this.tag)) {
      throw new Error('Unsupported state or unable to authenticate data');
    }
  } else {
    this.tag = tag;
  }
};
Cipher.prototype.getAuthTag = function () {
  if(this._decrypt || this.tag === null) {
    throw new Error('Attempting to get auth tag in unsupported state');
  }
  return this.tag;
};
Cipher.prototype.setAuthTag = function setAuthTag (tag) {
  if (this._decrypt) {
    this.tag = tag;
  } else {
    throw new Error('Attempting to set auth tag in unsupported state');
  }
};
function padAmount(len) {
  var rem = len % 16;
  if (!rem) {
    return 0;
  }
  return 16 - rem;
}
function xorTest(a, b) {
  var out = 0;
  if (a.length !== b.length) {
    out++;
  }
  var len = Math.min(a.length, b.length);
  var i = -1;
  while (++i < len) {
    out += (a[i] ^ b[i]);
  }
  return out;
}
