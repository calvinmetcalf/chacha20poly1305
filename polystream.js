var inherits = require('inherits');

var CipherBase = require('./cipherbase');
var Poly1305 = require('./poly1305');
module.exports = PolyStream;
inherits(PolyStream, CipherBase);
function PolyStream (key) {
  if (!(this instanceof PolyStream)) {
    return new PolyStream(key);
  }
  CipherBase.call(this, true);
  this.poly = new Poly1305(key);
}
PolyStream.prototype._update = function (data) {
  this.poly.update(data);
};

PolyStream.prototype._final = function () {
  return this.poly.finish();
};
