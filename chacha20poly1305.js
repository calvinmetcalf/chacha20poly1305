/* chacha20 - 256 bits */

// Written in 2014 by Devi Mandiri. Public domain.
//
// Implementation derived from chacha-ref.c version 20080118
// See for details: http://cr.yp.to/chacha/chacha-20080128.pdf

var Chacha20KeySize   = 32;
var Chacha20NonceSize =  8;

var Chacha20Ctx  = function() {
  this.input = new Array(16);
};

function load32(x, i) {
  return x[i] | (x[i+1]<<8) | (x[i+2]<<16) | (x[i+3]<<24);
}

function store32(x, i, u) {
  x[i]   = u & 0xff; u >>>= 8;
  x[i+1] = u & 0xff; u >>>= 8;
  x[i+2] = u & 0xff; u >>>= 8;
  x[i+3] = u & 0xff;
}

function plus(v, w) {
  return (v + w) >>> 0;
}

function rotl32(v, c) {
  return ((v << c) >>> 0) | (v >>> (32 - c));
}

function quarterRound(x, a, b, c, d) {
  x[a] = plus(x[a], x[b]); x[d] = rotl32(x[d] ^ x[a], 16);
  x[c] = plus(x[c], x[d]); x[b] = rotl32(x[b] ^ x[c], 12);
  x[a] = plus(x[a], x[b]); x[d] = rotl32(x[d] ^ x[a],  8);
  x[c] = plus(x[c], x[d]); x[b] = rotl32(x[b] ^ x[c],  7);
}

function chacha20_keysetup(ctx, key) {
  ctx.input[0] = 1634760805;
  ctx.input[1] =  857760878;
  ctx.input[2] = 2036477234;
  ctx.input[3] = 1797285236;
  for (var i = 0; i < 8; i++) {
    ctx.input[i+4] = load32(key, i*4);
  }
}

function chacha20_ivsetup(ctx, iv) {
  ctx.input[12] = 0;
  ctx.input[13] = 0;
  ctx.input[14] = load32(iv, 0);
  ctx.input[15] = load32(iv, 4);
}

function chacha20_encrypt(ctx, dst, src, len) {
  var x = new Array(16);
  var buf = new Array(64);
  var i = 0, dpos = 0, spos = 0;

  while (len > 0 ) {
    for (i = 16; i--;) x[i] = ctx.input[i];
    for (i = 20; i > 0; i -= 2) {
      quarterRound(x, 0, 4, 8,12);
      quarterRound(x, 1, 5, 9,13);
      quarterRound(x, 2, 6,10,14);
      quarterRound(x, 3, 7,11,15);
      quarterRound(x, 0, 5,10,15);
      quarterRound(x, 1, 6,11,12);
      quarterRound(x, 2, 7, 8,13);
      quarterRound(x, 3, 4, 9,14);
    }
    for (i = 16; i--;) x[i] += ctx.input[i];
    for (i = 16; i--;) store32(buf, 4*i, x[i]);

    ctx.input[12] = plus(ctx.input[12], 1);
    if (!ctx.input[12]) {
      ctx.input[13] = plus(ctx.input[13], 1);
    }
    if (len <= 64) {
      for (i = len; i--;) {
        dst[i+dpos] = src[i+spos] ^ buf[i];
      }
      return;
    }
    for (i = 64; i--;) {
      dst[i+dpos] = src[i+spos] ^ buf[i];
    }
    len -= 64;
    spos += 64;
    dpos += 64;
  }
}

function chacha20_decrypt(ctx, dst, src, len) {
  chacha20_encrypt(ctx, dst, src, len);
}

function chacha20_keystream(ctx, dst, len) {
  for (var i = 0; i < len; ++i) dst[i] = 0;
  chacha20_encrypt(ctx, dst, dst, len);
}

/* poly1305 */
 
// Written in 2014 by Devi Mandiri. Public domain.
//
// Implementation derived from poly1305-donna-16.h
// See for details: https://github.com/floodyberry/poly1305-donna
 
var Poly1305KeySize = 32;
var Poly1305TagSize = 16;
 
var Poly1305Ctx = function() {
  this.buffer = new Array(Poly1305TagSize);
  this.leftover = 0;
  this.r = new Array(10);
  this.h = new Array(10);
  this.pad = new Array(8);
  this.finished = 0;
};
 
function U8TO16(p, pos) {
  return ((p[pos] & 0xff) & 0xffff) | (((p[pos+1] & 0xff) & 0xffff) << 8);
}
 
function U16TO8(p, pos, v) {
  p[pos]   = (v      ) & 0xff;
  p[pos+1] = (v >>> 8) & 0xff;
}
 
function poly1305_init(ctx, key) {
  var t = [], i = 0;
 
  for (i = 8; i--;) t[i] = U8TO16(key, i*2);
 
  ctx.r[0] =   t[0]                         & 0x1fff;
  ctx.r[1] = ((t[0] >>> 13) | (t[1] <<  3)) & 0x1fff;
  ctx.r[2] = ((t[1] >>> 10) | (t[2] <<  6)) & 0x1f03;
  ctx.r[3] = ((t[2] >>>  7) | (t[3] <<  9)) & 0x1fff;
  ctx.r[4] = ((t[3] >>>  4) | (t[4] << 12)) & 0x00ff;
  ctx.r[5] =  (t[4] >>>  1)                 & 0x1ffe;
  ctx.r[6] = ((t[4] >>> 14) | (t[5] <<  2)) & 0x1fff;
  ctx.r[7] = ((t[5] >>> 11) | (t[6] <<  5)) & 0x1f81;
  ctx.r[8] = ((t[6] >>>  8) | (t[7] <<  8)) & 0x1fff;
  ctx.r[9] =  (t[7] >>>  5)                 & 0x007f;
 
  for (i = 8; i--;) {
    ctx.h[i]   = 0;
    ctx.pad[i] = U8TO16(key, 16+(2*i));
  }
  ctx.h[8] = 0;
  ctx.h[9] = 0;
  ctx.leftover = 0;
  ctx.finished = 0;  
}
 
function poly1305_blocks(ctx, m, mpos, bytes) {
  var hibit = ctx.finished ? 0 : (1 << 11);
  var t = [], d = [], c = 0, i = 0, j = 0;
 
  while (bytes >= Poly1305TagSize) {
    for (i = 8; i--;) t[i] = U8TO16(m, i*2+mpos);
 
    ctx.h[0] +=   t[0]                         & 0x1fff;
    ctx.h[1] += ((t[0] >>> 13) | (t[1] <<  3)) & 0x1fff;
    ctx.h[2] += ((t[1] >>> 10) | (t[2] <<  6)) & 0x1fff;
    ctx.h[3] += ((t[2] >>>  7) | (t[3] <<  9)) & 0x1fff;
    ctx.h[4] += ((t[3] >>>  4) | (t[4] << 12)) & 0x1fff;
    ctx.h[5] +=  (t[4] >>>  1)                 & 0x1fff;
    ctx.h[6] += ((t[4] >>> 14) | (t[5] <<  2)) & 0x1fff;
    ctx.h[7] += ((t[5] >>> 11) | (t[6] <<  5)) & 0x1fff;
    ctx.h[8] += ((t[6] >>>  8) | (t[7] <<  8)) & 0x1fff;
    ctx.h[9] +=  (t[7] >>>  5)                 | hibit;
 
    for (i = 0, c = 0; i < 10; i++) {
      d[i] = c;
      for (j = 0; j < 10; j++) {
        d[i] += (ctx.h[j] & 0xffffffff) * ((j <= i) ? ctx.r[i-j] : (5 * ctx.r[i+10-j]));
        if (j === 4) {
          c = (d[i] >>> 13);
          d[i] &= 0x1fff;
        }
      }
      c += (d[i] >>> 13);
      d[i] &= 0x1fff;
    }
    c = ((c << 2) + c);
    c += d[0];
    d[0] = ((c & 0xffff) & 0x1fff);
    c = (c >>> 13);
    d[1] += c;
 
    for (i = 10; i--;) ctx.h[i] = d[i] & 0xffff;
 
    mpos += Poly1305TagSize;
    bytes -= Poly1305TagSize;
  }
}
 
function poly1305_update(ctx, m, bytes) {
  var want = 0, i = 0, mpos = 0;
 
  if (ctx.leftover) {
    want = (Poly1305TagSize - ctx.leftover);
    if (want > bytes)
      want = bytes;
    for (i = want; i--;) {
      ctx.buffer[ctx.leftover+i] = m[i+mpos];
    }
    bytes -= want;
    mpos += want;
    ctx.leftover += want;
    if (ctx.leftover < Poly1305TagSize)
      return;
    poly1305_blocks(ctx, ctx.buffer, 0, Poly1305TagSize);
    ctx.leftover = 0;    
  }
 
  if (bytes >= Poly1305TagSize) {
    want = (bytes & ~(Poly1305TagSize - 1));
    poly1305_blocks(ctx, m, mpos, want);
    mpos += want;
    bytes -= want;
  }
 
  if (bytes) {
    for (i = bytes; i--;) {
      ctx.buffer[ctx.leftover+i] = m[i+mpos];
    }
    ctx.leftover += bytes;
  }
}
 
function poly1305_finish(ctx, mac) {
  var g = [], c = 0, mask = 0, f = 0, i = 0;
 
  if (ctx.leftover) {
    i = ctx.leftover;
    ctx.buffer[i++] = 1;
    for (; i < Poly1305TagSize; i++) {
      ctx.buffer[i] = 0;
    }
    ctx.finished = 1;
    poly1305_blocks(ctx, ctx.buffer, 0, Poly1305TagSize);
  }
 
  c = ctx.h[1] >>> 13;
  ctx.h[1] &= 0x1fff;
  for (i = 2; i < 10; i++) {
    ctx.h[i] += c;
    c = ctx.h[i] >>> 13;
    ctx.h[i] &= 0x1fff;
  }
  ctx.h[0] += (c * 5);
  c = ctx.h[0] >>> 13;
  ctx.h[0] &= 0x1fff;
  ctx.h[1] += c;
  c = ctx.h[1] >>> 13;
  ctx.h[1] &= 0x1fff;
  ctx.h[2] += c;
 
  g[0] = ctx.h[0] + 5;
  c = g[0] >>> 13;
  g[0] &= 0x1fff;
  for (i = 1; i < 10; i++) {
    g[i] = ctx.h[i] + c;
    c = g[i] >>> 13;
    g[i] &= 0x1fff;
  }
  g[9] -= (1 << 13);
  g[9] &= 0xffff;
 
  mask = (g[9] >>> 15) - 1;
  for (i = 10; i--;) g[i] &= mask;
  mask = ~mask;
  for (i = 10; i--;) {
    ctx.h[i] = (ctx.h[i] & mask) | g[i];
  }
 
  ctx.h[0] = ((ctx.h[0]      ) | (ctx.h[1] << 13)) & 0xffff;
  ctx.h[1] = ((ctx.h[1] >>  3) | (ctx.h[2] << 10)) & 0xffff;
  ctx.h[2] = ((ctx.h[2] >>  6) | (ctx.h[3] <<  7)) & 0xffff;
  ctx.h[3] = ((ctx.h[3] >>  9) | (ctx.h[4] <<  4)) & 0xffff;
  ctx.h[4] = ((ctx.h[4] >> 12) | (ctx.h[5] <<  1) | (ctx.h[6] << 14)) & 0xffff;
  ctx.h[5] = ((ctx.h[6] >>  2) | (ctx.h[7] << 11)) & 0xffff;
  ctx.h[6] = ((ctx.h[7] >>  5) | (ctx.h[8] <<  8)) & 0xffff;
  ctx.h[7] = ((ctx.h[8] >>  8) | (ctx.h[9] <<  5)) & 0xffff;
 
  f = (ctx.h[0] & 0xffffffff) + ctx.pad[0];
  ctx.h[0] = f & 0xffff;
  for (i = 1; i < 8; i++) {
    f = (ctx.h[i] & 0xffffffff) + ctx.pad[i] + (f >>> 16);
    ctx.h[i] = f & 0xffff;
  }
 
  for (i = 8; i--;) {
    U16TO8(mac, i*2, ctx.h[i]);
    ctx.pad[i] = 0;
  }
  for (i = 10; i--;) {
    ctx.h[i] = 0;
    ctx.r[i] = 0;
  }
}
 
function poly1305_auth(mac, m, bytes, key) {
  var ctx = new Poly1305Ctx();
  poly1305_init(ctx, key);
  poly1305_update(ctx, m, bytes);
  poly1305_finish(ctx, mac);
}
 
function poly1305_verify(mac1, mac2) {
  var dif = 0;
  for (var i = 0; i < 16; i++) {
    dif |= (mac1[i] ^ mac2[i]);
  }
  dif = (dif - 1) >>> 31;
  return (dif & 1);
}

/* chacha20poly1305 AEAD */

// Written in 2014 by Devi Mandiri. Public domain.

var AeadCtx = function(key) {
  this.key = key;
};

function aead_init(c20ctx, key, nonce) {
  chacha20_keysetup(c20ctx, key);
  chacha20_ivsetup(c20ctx, nonce);

  var subkey = [];
  chacha20_keystream(c20ctx, subkey, 64);

  return subkey.slice(0, 32);
}

function store64(dst, pos, num) {
  var hi = 0;
  var lo = num >>> 0; // 2^53 should be huge enough
  if ((+(Math.abs(num))) >= 1) {
    if (num > 0) {
      hi = ((Math.min((+(Math.floor(num/4294967296))), 4294967295))|0) >>> 0;
    } else {
      hi = (~~((+(Math.ceil((num - +(((~~(num)))>>>0))/4294967296))))) >>> 0;
    }
  }
  dst[pos]   = lo & 0xff; lo >>>= 8;
  dst[pos+1] = lo & 0xff; lo >>>= 8;
  dst[pos+2] = lo & 0xff; lo >>>= 8;
  dst[pos+3] = lo & 0xff;
  dst[pos+4] = hi & 0xff; hi >>>= 8;
  dst[pos+5] = hi & 0xff; hi >>>= 8;
  dst[pos+6] = hi & 0xff; hi >>>= 8;
  dst[pos+7] = hi & 0xff;
}

function aead_mac(key, ciphertext, data) {
  var clen = ciphertext.length;
  var dlen = data.length;
  var m = new Array(clen + dlen + 16);
  var i = dlen;

  for (; i--;) m[i] = data[i];
  store64(m, dlen, dlen);

  for (i = clen; i--;) m[dlen+8+i] = ciphertext[i];
  store64(m, clen+dlen+8, clen);

  var mac = [];
  poly1305_auth(mac, m, m.length, key);

  return mac;
}

function aead_encrypt(ctx, nonce, input, ad) {
  var c = new Chacha20Ctx();
  var key = aead_init(c, ctx.key, nonce);

  var ciphertext = [];
  chacha20_encrypt(c, ciphertext, input, input.length);

  var mac = aead_mac(key, ciphertext, ad);

  var out = [];
  out = out.concat(ciphertext, mac);

  return out;
}

function aead_decrypt(ctx, nonce, ciphertext, ad) {
  var c = new Chacha20Ctx();
  var key = aead_init(c, ctx.key, nonce);
  var clen = ciphertext.length - Poly1305TagSize;
  var digest = ciphertext.slice(clen);
  var mac = aead_mac(key, ciphertext.slice(0, clen), ad);

  if (poly1305_verify(digest, mac) !== 1) return false;

  var out = [];
  chacha20_decrypt(c, out, ciphertext, clen);
  return out;
}


//--------------------------- test -----------------------------//
function fromHex(h) {
  h.replace(/([^0-9a-f])/g, '');
  var out = [], len = h.length, w = '';
  for (var i = 0; i < len; i += 2) {
    w = h[i];
    if (((i+1) >= len) || typeof h[i+1] === 'undefined') {
        w += '0';
    } else {
        w += h[i+1];
    }
    out.push(parseInt(w, 16));
  }
  return out;
}

function bytesEqual(a, b) {
  var dif = 0;
  if (a.length !== b.length) return 0;
  for (var i = 0; i < a.length; i++) {
    dif |= (a[i] ^ b[i]);
  }
  dif = (dif - 1) >>> 31;
  return (dif & 1);
}

// All testVectors taken from http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04#page-11

function chacha20_test() {
  console.log('chacha20 test');
  var testVectors = [
    {
      key:       '0000000000000000000000000000000000000000000000000000000000000000',
      nonce:     '0000000000000000',
      keystream: '76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc'+
                 '8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11c'+
                 'c387b669b2ee6586'
    },
    {
      key:       '0000000000000000000000000000000000000000000000000000000000000001',
      nonce:     '0000000000000000',
      keystream: '4540f05a9f1fb296d7736e7b208e3c96eb4fe1834688d2604f450952'+
                 'ed432d41bbe2a0b6ea7566d2a5d1e7e20d42af2c53d792b1c43fea81'+
                 '7e9ad275ae546963'
    },
    {
      key:       '0000000000000000000000000000000000000000000000000000000000000000',
      nonce:     '0000000000000001',
      keystream: 'de9cba7bf3d69ef5e786dc63973f653a0b49e015adbff7134fcb7df1'+
                 '37821031e85a050278a7084527214f73efc7fa5b5277062eb7a0433e'+
                 '445f41e3'
    },
    {
      key:       '0000000000000000000000000000000000000000000000000000000000000000',
      nonce:     '0100000000000000',
      keystream: 'ef3fdfd6c61578fbf5cf35bd3dd33b8009631634d21e42ac33960bd1'+
                 '38e50d32111e4caf237ee53ca8ad6426194a88545ddc497a0b466e7d'+
                 '6bbdb0041b2f586b'
    },
    {
      key:       '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
      nonce:     '0001020304050607',
      keystream: 'f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56'+
                 'f85ac3c134a4547b733b46413042c9440049176905d3be59ea1c53f1'+
                 '5916155c2be8241a38008b9a26bc35941e2444177c8ade6689de9526'+
                 '4986d95889fb60e84629c9bd9a5acb1cc118be563eb9b3a4a472f82e'+
                 '09a7e778492b562ef7130e88dfe031c79db9d4f7c7a899151b9a4750'+
                 '32b63fc385245fe054e3dd5a97a5f576fe064025d3ce042c566ab2c5'+
                 '07b138db853e3d6959660996546cc9c4a6eafdc777c040d70eaf46f7'+
                 '6dad3979e5c5360c3317166a1c894c94a371876a94df7628fe4eaaf2'+
                 'ccb27d5aaae0ad7ad0f9d4b6ad3b54098746d4524d38407a6deb3ab7'+
                 '8fab78c9'
    },
  ];

  for (var i = 0; i < testVectors.length; i++) {
    var key = fromHex(testVectors[i].key);
    var nonce = fromHex(testVectors[i].nonce);
    var expected = fromHex(testVectors[i].keystream);
    var out = [];

    var ctx = new Chacha20Ctx();

    chacha20_keysetup(ctx, key);
    chacha20_ivsetup(ctx, nonce);
    chacha20_keystream(ctx, out, expected.length);

    if (bytesEqual(expected, out) != 1) {
      console.log('error: ', i);
      console.log('want:\n', expected.join(' '));
      console.log('got :\n', out.join(' '), '\n');  
    } else {
      console.log(i, 'OK');
    }
  }
}

function poly1305_test() {
  console.log('poly1305 test');
  var testVectors = [
    {
      input: '0000000000000000000000000000000000000000000000000000000000000000',
      key:   '746869732069732033322d62797465206b657920666f7220506f6c7931333035',
      tag:   '49ec78090e481ec6c26b33b91ccc0307'
    },
    {
      input: '48656c6c6f20776f726c6421',
      key:   '746869732069732033322d62797465206b657920666f7220506f6c7931333035',
      tag:   'a6f745008f81c916a20dcc74eef2b2f0'
    }
  ];

  for (var i = 0; i < testVectors.length; i++) {
    var input = fromHex(testVectors[i].input);
    var key = fromHex(testVectors[i].key);
    var expected = fromHex(testVectors[i].tag);

    var out = [];
    poly1305_auth(out, input, input.length, key);;

    if (poly1305_verify(expected, out) != 1) {
      console.log('error: ', i);
      console.log('want:\n', expected.join(' '));
      console.log('got :\n', out.join(' '), '\n');  
    } else {
      console.log(i, 'OK');
    }
  }
}

function aead_test() {
  console.log('aead test');
  var testVectors = {
    key:   fromHex('4290bcb154173531f314af57f3be3b5006da371ece272afa1b5dbdd1100a1007'),
    input: fromHex('86d09974840bded2a5ca'),
    nonce: fromHex('cd7cf67be39c794a'),
    ad:    fromHex('87e229d4500845a079c0'),
    output: fromHex('e3e446f7ede9a19b62a4677dabf4e3d24b876bb284753896e1d6'),
  };

  var ctx = new AeadCtx(testVectors.key);

  var ciphertext = aead_encrypt(ctx, testVectors.nonce, testVectors.input, testVectors.ad);

  if (bytesEqual(testVectors.output, ciphertext) !== 1) {
    console.log('encryption error: ');
    console.log('want:\n', testVectors.output.join(' '));
    console.log('got :\n', ciphertext.join(' '), '\n');
  } else {
    console.log('encryption OK');
  }

  var plaintext = aead_decrypt(ctx, testVectors.nonce, ciphertext, testVectors.ad);

  if (bytesEqual(testVectors.input, plaintext) !== 1) {
    console.log('dencryption error: ');
    console.log('want:\n', testVectors.input.join(' '));
    console.log('got :\n', plaintext.join(' '), '\n');
  } else {
    console.log('decryption OK');
  }
}

chacha20_test();
poly1305_test();
aead_test();
