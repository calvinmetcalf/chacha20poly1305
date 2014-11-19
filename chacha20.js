
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
  //https://tools.ietf.org/html/draft-irtf-cfrg-chacha20-poly1305-01#section-2.3
  this.input = {
    a:SIMD.int32x4(1634760805, 857760878, 2036477234, 1797285236),
    b:SIMD.int32x4(key.readUInt32LE(0), key.readUInt32LE(4), key.readUInt32LE(8), key.readUInt32LE(12)),
    c:SIMD.int32x4(key.readUInt32LE(16), key.readUInt32LE(20), key.readUInt32LE(24), key.readUInt32LE(28)),
    d:SIMD.int32x4(0, nonce.readUInt32LE(0), nonce.readUInt32LE(4), nonce.readUInt32LE(8))
  };
  this.output = new Buffer(64);
  this.cachePos = 64;
}
var s16 = SIMD.int32x4(16, 16, 16, 16);
var s12 = SIMD.int32x4(12, 12, 12, 12);
var s8 = SIMD.int32x4(8, 8, 8, 8);
var s7 = SIMD.int32x4(7, 7, 7, 7);
var s32 = SIMD.int32x4(32, 32, 32, 32);
Chacha20.prototype.quarterRound = function(a, b, c, d) {
  // well 4 quarter rounds at once
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


function toNodeBuffer(output, pos, int4){
  output.writeInt32LE(int4.x, pos++ << 2);
  output.writeInt32LE(int4.y, pos++ << 2);
  output.writeInt32LE(int4.z, pos++ << 2);
  output.writeInt32LE(int4.w, pos++ << 2);
}
Chacha20.prototype.rounds = function () {
  var out = {
    a:this.input.a,
    b:this.input.b,
    c:this.input.c,
    d:this.input.d
  };
  var i = -1;
  while (++i < 10) {
    // do the strait round
    out = this.quarterRound(out.a, out.b, out.c, out.d);
    // swizzle over to diagnal
    out.b = SIMD.int32x4.swizzle(out.b, 1, 2, 3, 0);
    out.c = SIMD.int32x4.swizzle(out.c, 2, 3, 0, 1);
    out.d = SIMD.int32x4.swizzle(out.d, 3, 0, 1, 2);
    // do the diagnal one
    out = this.quarterRound(out.a, out.b, out.c, out.d);
    out.d = SIMD.int32x4.swizzle(out.d, 1, 2, 3, 0);
    out.c = SIMD.int32x4.swizzle(out.c, 2, 3, 0, 1);
    out.b = SIMD.int32x4.swizzle(out.b, 3, 0, 1, 2);
  }
  out.a = SIMD.int32x4.add(out.a, this.input.a);
  out.b = SIMD.int32x4.add(out.b, this.input.b);
  out.c = SIMD.int32x4.add(out.c, this.input.c);
  out.d = SIMD.int32x4.add(out.d, this.input.d);
  toNodeBuffer(this.output, 0, out.a);
  toNodeBuffer(this.output, 4, out.b);
  toNodeBuffer(this.output, 8, out.c);
  toNodeBuffer(this.output, 12, out.d);
};
Chacha20.prototype.getBytes = function(len) {
  var dpos = 0;
  var dst = new Buffer(len);
  // was the last call less then a full block?
  // if yes we will start off filling dst with 
  // the left overs

  var cacheLen = 64 - this.cachePos;
  if (cacheLen) {
    if (cacheLen >= len) {
      this.output.copy(dst, 0, this.cachePos, this.cachePos + len);
      this.cachePos += len;
      return dst;
    } else {
      this.output.copy(dst, 0, this.cachePos);
      len -= cacheLen;
      dpos += cacheLen;
      this.cachePos = 64;
    }
  }
  while (len > 0 ) {
    // this does 20 rounds and fills up a buffer named output
    this.rounds();
    // increment the counter
    this.input.d =  SIMD.int32x4.withX(this.input.d, this.input.d.x + 1);
    // we have gone through all the int32 numbers back to 0
    if (!this.input.d.x) {
      throw new Error('counter is exausted');
    }
    if (len <= 64) {
      this.output.copy(dst, dpos, 0, len);
      if (len < 64) {
        // we have some left overs
        this.cachePos = len;
      }      
      return dst;
    }
    this.output.copy(dst, dpos);
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