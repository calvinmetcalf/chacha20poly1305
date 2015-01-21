var Chacha20 = require('./chacha20');
var inherits = require('inherits');
var CipherBase = require('./cipherbase');
inherits(ChaChaStream, CipherBase);
module.exports = ChaChaStream;
function ChaChaStream (key, iv) {
  if (!(this instanceof ChaChaStream)) {
    return new ChaChaStream(key, iv);
  }
  CipherBase.call(this);
  this.chacha = new Chacha20(key, iv);
}
ChaChaStream.prototype._update = function (chunk) {
  var len = chunk.length;
  if (!len) {
    return;
  }
  var pad = this.chacha.getBytes(len);
  var i = -1;
  while (++i < len) {
    pad[i] ^= chunk[i];
  }
  return pad;
  };