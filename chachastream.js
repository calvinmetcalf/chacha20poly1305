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
ChaChaStream.prototype._transform = function (chunk, _, next) {
  if (!chunk.length) {
    return next();
  }
  this.chacha.xorBuffer(chunk);
  this.push(chunk);
  next();
};