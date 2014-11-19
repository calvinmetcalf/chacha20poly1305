function ROTATE(v, c) {
  return (v << c) | (v >>> (32 - c));
}
module.exports = Chacha20;
function Chacha20(key, nonce) {
  this.input = new Uint32Array(16);

  // https://tools.ietf.org/html/draft-irtf-cfrg-chacha20-poly1305-01#section-2.3
  this.input[0] = 1634760805;
  this.input[1] =  857760878;
  this.input[2] = 2036477234;
  this.input[3] = 1797285236;
  this.input[4] = key.readUInt32LE(0);
  this.input[5] = key.readUInt32LE(4);
  this.input[6] = key.readUInt32LE(8);
  this.input[7] = key.readUInt32LE(12);
  this.input[8] = key.readUInt32LE(16);
  this.input[9] = key.readUInt32LE(20);
  this.input[10] = key.readUInt32LE(24);
  this.input[11] = key.readUInt32LE(28);
  this.input[12] = 0;
  this.input[13] = nonce.readUInt32LE(0);
  this.input[14] = nonce.readUInt32LE(4);
  this.input[15] = nonce.readUInt32LE(8);
  this.cache = new Buffer(64);
  this.cacheLen = 0;
  this.cacheStart = 0;
  this.cacheEnd = 0;
}

Chacha20.prototype.quarterRound = function(x, a, b, c, d) {
  x[a] += x[b]; x[d] = ROTATE(x[d] ^ x[a], 16);
  x[c] += x[d]; x[b] = ROTATE(x[b] ^ x[c], 12);
  x[a] += x[b]; x[d] = ROTATE(x[d] ^ x[a],  8);
  x[c] += x[d]; x[b] = ROTATE(x[b] ^ x[c],  7);
};

Chacha20.prototype.getBytes = function(len) {
  var dpos = 0;
  var dst = new Buffer(len);
  dst.fill(0);
  var cacheLen = this.cacheEnd - this.cacheStart;
  if (cacheLen) {
    if (cacheLen >= len) {
      this.cache.copy(dst, 0, this.cacheStart, this.cacheEnd);
      this.cacheStart += len;
      return dst;
    } else {
      this.cache.copy(dst, 0, this.cacheStart, this.cacheStart + cacheLen);
      len -= cacheLen;
      dpos += cacheLen;
      this.cacheStart = this.cacheEnd = 0;
    }
  }
  var x = new Uint32Array(16);
  var output = new Buffer(64);
  var i, spos = 0;

  while (len > 0 ) {
    for (i = 16; i--;) x[i] = this.input[i];
    for (i = 20; i > 0; i -= 2) {
      this.quarterRound(x, 0, 4, 8,12);
      this.quarterRound(x, 1, 5, 9,13);
      this.quarterRound(x, 2, 6,10,14);
      this.quarterRound(x, 3, 7,11,15);

      this.quarterRound(x, 0, 5,10,15);
      this.quarterRound(x, 1, 6,11,12);
      this.quarterRound(x, 2, 7, 8,13);
      this.quarterRound(x, 3, 4, 9,14);
    }
    for (i = 16; i--;) x[i] += this.input[i];
    for (i = 16; i--;) output.writeUInt32LE(x[i], 4*i);

    this.input[12] += 1;
    if (!this.input[12]) {
      throw new Error('counter is exausted');
    }
    if (len <= 64) {
      output.copy(dst, dpos, 0, len);
      if (len < 64) {
        output.copy(this.cache, 0, len);
        this.cacheEnd = 64 - len;
        this.cacheStart = 0;
      }      
      return dst;
    }
    output.copy(dst, dpos);
    len -= 64;
    dpos += 64;
  }
  return dst;
};

Chacha20.prototype.keystream = function(dst, len) {
  var pad = this.getBytes(len);
  var i = -1;
  pad.copy(dst, 0, len);
  while (++i < len) {
    dst[i] = pad[i];
  }
};