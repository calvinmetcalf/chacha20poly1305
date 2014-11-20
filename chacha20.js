var i32x4 = new Int32Array(4);
function ROTATE(v, c) {
  var right = s32.clone(i32x4).sub(c).shiftRightLogicalBy(v);
  v.shiftLeft(c).xor(right);
}

var SIMD = require('./simd');
module.exports = Chacha20;
function Chacha20(key, nonce) {
  key = new Buffer(key);
  nonce = new Buffer(nonce);
  //https://tools.ietf.org/html/draft-irtf-cfrg-chacha20-poly1305-01#section-2.3
  this.input = {
    a:SIMD.int32x4(1634760805, 857760878, 2036477234, 1797285236),
    b:SIMD.int32x4(key.readUInt32LE(0), key.readUInt32LE(4), key.readUInt32LE(8), key.readUInt32LE(12)),
    c:SIMD.int32x4(key.readUInt32LE(16), key.readUInt32LE(20), key.readUInt32LE(24), key.readUInt32LE(28)),
    d:SIMD.int32x4(0, nonce.readUInt32LE(0), nonce.readUInt32LE(4), nonce.readUInt32LE(8))
  };
  this.output = new Buffer(64);
  this.cachePos = 64;
  this.working = new ArrayBuffer(64);
}
var s16 = SIMD.int32x4(16, 16, 16, 16);
var s12 = SIMD.int32x4(12, 12, 12, 12);
var s8 = SIMD.int32x4(8, 8, 8, 8);
var s7 = SIMD.int32x4(7, 7, 7, 7);
var s32 = SIMD.int32x4(32, 32, 32, 32);
Chacha20.prototype.quarterRound = function(a, b, c, d) {
  // well 4 quarter rounds at once
  a.add(b); 
  ROTATE(d.xor(a), s16);
  c.add(d); 
  ROTATE(b.xor(c), s12);
  a.add(b);
  ROTATE(d.xor(a),  s8);
  c.add(d); 
  ROTATE(b.xor(c),  s7);
};


function toNodeBuffer(output, pos, int4){
  output.writeInt32LE(int4.x, pos++ << 2);
  output.writeInt32LE(int4.y, pos++ << 2);
  output.writeInt32LE(int4.z, pos++ << 2);
  output.writeInt32LE(int4.w, pos++ << 2);
}
Chacha20.prototype.rounds = function () {
  var out = {
    a:this.input.a.clone(new Int32Array(this.working, 0, 4)),
    b:this.input.b.clone(new Int32Array(this.working, 16, 4)),
    c:this.input.c.clone(new Int32Array(this.working, 32, 4)),
    d:this.input.d.clone(new Int32Array(this.working, 48, 4))
  };
  var i = -1;
  while (++i < 10) {
    // do the strait round
    this.quarterRound(out.a, out.b, out.c, out.d);
    // swizzle over to diagnal
    out.b.swizzle(1, 2, 3, 0);
    out.c.swizzle(2, 3, 0, 1);
    out.d.swizzle(3, 0, 1, 2);
    // do the diagnal one
    this.quarterRound(out.a, out.b, out.c, out.d);
    out.d .swizzle(1, 2, 3, 0);
    out.c.swizzle(2, 3, 0, 1);
    out.b.swizzle(3, 0, 1, 2);
  }
  out.a.add(this.input.a);
  out.b.add(this.input.b);
  out.c.add(this.input.c);
  out.d.add(this.input.d);
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
    this.input.d.withX(this.input.d.x + 1);
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