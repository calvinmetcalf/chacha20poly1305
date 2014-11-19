
function ROTATE(v, c) {
  return SIMD.int32x4.or(shiftLeft(v, c), shiftRightLogical(v, SIMD.int32x4.sub(s32, c)));
}
function shiftRightLogical(a, b) {
  var x = a.x >>> b.x;
  var y = a.y >>> b.y;
  var z = a.z >>> b.z;
  var w = a.w >>> b.w;
  return SIMD.int32x4(x, y, z, w);
}
function shiftLeft(a, b) {
  var x = a.x << b.x;
  var y = a.y << b.y;
  var z = a.z << b.z;
  var w = a.w << b.w;
  return SIMD.int32x4(x, y, z, w);
}
var SIMD = global.SIMD || require('./simd');
module.exports = Chacha20;
function Chacha20(key, nonce) {
  //this.input = new Uint32Array(16);

  //https://tools.ietf.org/html/draft-irtf-cfrg-chacha20-poly1305-01#section-2.3
  this.input = {
    a:SIMD.int32x4(1634760805, 857760878, 2036477234, 1797285236),
    b:SIMD.int32x4(key.readUInt32LE(0), key.readUInt32LE(4), key.readUInt32LE(8), key.readUInt32LE(12)),
    c:SIMD.int32x4( key.readUInt32LE(16), key.readUInt32LE(20), key.readUInt32LE(24), key.readUInt32LE(28)),
    d:SIMD.int32x4(0, nonce.readUInt32LE(0), nonce.readUInt32LE(4), nonce.readUInt32LE(8))
  };
  // this.input[0] = 1634760805;
  // this.input[1] =  857760878;
  // this.input[2] = 2036477234;
  // this.input[3] = 1797285236;
  // this.input[4] = key.readUInt32LE(0);
  // this.input[5] = key.readUInt32LE(4);
  // this.input[6] = key.readUInt32LE(8);
  // this.input[7] = key.readUInt32LE(12);
  // this.input[8] = key.readUInt32LE(16);
  // this.input[9] = key.readUInt32LE(20);
  // this.input[10] = key.readUInt32LE(24);
  // this.input[11] = key.readUInt32LE(28);
  // this.input[12] = 0;
  // this.input[13] = nonce.readUInt32LE(0);
  // this.input[14] = nonce.readUInt32LE(4);
  // this.input[15] = nonce.readUInt32LE(8);
  this.cache = new Buffer(64);
  this.cacheLen = 0;
  this.cacheStart = 0;
  this.cacheEnd = 0;
}
var s16 = SIMD.int32x4(16, 16, 16, 16);
var s12 = SIMD.int32x4(12, 12, 12, 12);
var s8 = SIMD.int32x4(8, 8, 8, 8);
var s7 = SIMD.int32x4(7, 7, 7, 7);
var s32 = SIMD.int32x4(32, 32, 32, 32);
Chacha20.prototype._quarterRound = function(a, b, c, d) {
  a = SIMD.int32x4.add(a, b); 
  d = ROTATE(SIMD.int32x4.xor(d, a), s16);
  c = SIMD.int32x4.add(c, d); 
  b = ROTATE(SIMD.int32x4.xor(b, c), s12);
  a = SIMD.int32x4.add(a, b);
  d = ROTATE(SIMD.int32x4.xor(d, a),  s8);
  c = SIMD.int32x4.add(c, d); 
  b = ROTATE(SIMD.int32x4.xor(b, c),  s7);
  return {a:a, b:b, c:c, d:d};
};
function makeSimd(a) {
  return SIMD.int32x4(a, 0, 0, 0);
}
Chacha20.prototype.quarterRound = function(x, a, b, c, d) {
  var out = this._quarterRound(makeSimd(x[a]), makeSimd(x[b]), makeSimd(x[c]), makeSimd(x[d]));
  x[a] = out[0].x;
  x[b] = out[1].x;
  x[c] = out[2].x;
  x[d] = out[3].x;
};
Chacha20.prototype.round = function (x, output) {
  var out = {
    a:this.input.a,
    b:this.input.b,
    c:this.input.c,
    d:this.input.d
  };
  for (var i = 20; i > 0; i -= 2) {
    out = this._quarterRound(out.a, out.b, out.c, out.d);
    out.b = SIMD.int32x4.swizzle(out.b, 1, 2, 3, 0);
    out.c = SIMD.int32x4.swizzle(out.c, 2, 3, 0, 1);
    out.d = SIMD.int32x4.swizzle(out.d, 3, 0, 1, 2);
    out = this._quarterRound(out.a, out.b, out.c, out.d);
    out.d = SIMD.int32x4.swizzle(out.d, 1, 2, 3, 0);
    out.c = SIMD.int32x4.swizzle(out.c, 2, 3, 0, 1);
    out.b = SIMD.int32x4.swizzle(out.b, 3, 0, 1, 2);
  }
  out.a = SIMD.int32x4.add(out.a, this.input.a);
  out.b = SIMD.int32x4.add(out.b, this.input.b);
  out.c = SIMD.int32x4.add(out.c, this.input.c);
  out.d = SIMD.int32x4.add(out.d, this.input.d);
  SIMD.int32x4.store(x, 0, out.a);
  SIMD.int32x4.store(x, 4, out.b);
  SIMD.int32x4.store(x, 8, out.c);
  SIMD.int32x4.store(x, 12, out.d);
  i = -1;
  while (++i < 16) {
    output.writeUInt32LE(x[i], i << 2);
  }
  // x[0] = a.x + input[0];
  // x[1] = a.y + input[1];
  // x[2] = a.z + input[2];
  // x[3] = a.w + input[3];

  // x[4] = b.x + input[4];
  // x[5] = b.y + input[5];
  // x[6] = b.z + input[6];
  // x[7] = b.w + input[7];

  // x[8] = c.x + input[8];
  // x[9] = c.y + input[9];
  // x[10] = c.z + input[10];
  // x[11] = c.w + input[11];

  // x[12] = d.x + input[12];
  // x[13] = d.y + input[13];
  // x[14] = d.z + input[14];
  // x[15] = d.w + input[15];

  // this.quarterRound(x, 0, 4, 8,12);
  // this.quarterRound(x, 1, 5, 9,13);
  // this.quarterRound(x, 2, 6,10,14);
  // this.quarterRound(x, 3, 7,11,15);

  // this.quarterRound(x, 0, 5,10,15);
  // this.quarterRound(x, 1, 6,11,12);
  // this.quarterRound(x, 2, 7, 8,13);
  // this.quarterRound(x, 3, 4, 9,14);
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
    this.round(x, output);
    

    this.input.d =  SIMD.int32x4.withX(this.input.d, this.input.d.x + 1);
    if (!this.input.d.x) {
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