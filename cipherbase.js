var inherits = require('inherits');

var Transform = require('readable-stream').Transform;

inherits(CipherBase, Transform);
module.exports = CipherBase;
function CipherBase() {
  Transform.call(this);
}
CipherBase.prototype.update = function (data, inputEnd, outputEnc) {
  if (typeof data === 'string') {
    this.write(data, inputEnd);
  } else {
    var out = new Buffer(data.length);
    data.copy(out);
    this.write(out);
}
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
CipherBase.prototype.final = function (outputEnc) {
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