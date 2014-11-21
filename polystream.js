var inherits = require('inherits');

var Transform = require('readable-stream').Transform;
var Poly1305 = require('./poly1305');
module.exports = PolyStream;
inherits(PolyStream, Transform);
function PolyStream (key) {
  if (!(this instanceof PolyStream)) {
    return new PolyStream(key);
  }
  Transform.call(this);
  this.poly = new Poly1305(key);
}
PolyStream.prototype.update = function (data, enc) {
  this.write(data, enc);
  return this;
};
PolyStream.prototype._transform = function (data, _, next) {
  this.poly.update(data);
  next();
};

PolyStream.prototype._flush = function (next) {
  this.push(this.poly.finish());
  next();
};
PolyStream.prototype.digest = function (outputEnc) {
  this.end();
  var outData = new Buffer('');
  var chunk;
  while ((chunk = this.read())) {
    outData = Buffer.concat([outData, chunk]);
  }
  if (outputEnc) {
    outData = outData.toString(outputEnc);
  }
  return outData;
};
