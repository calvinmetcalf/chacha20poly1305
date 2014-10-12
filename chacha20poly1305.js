/* chacha20 - 256 bits */

// Written in 2014 by Devi Mandiri. Public domain.
//
// Implementation derived from chacha-ref.c version 20080118
// See for details: http://cr.yp.to/chacha/chacha-20080128.pdf

function U8TO32_LE(x, i) {
  return x[i] | (x[i+1]<<8) | (x[i+2]<<16) | (x[i+3]<<24);
}

function U32TO8_LE(x, i, u) {
  x[i]   = u; u >>>= 8;
  x[i+1] = u; u >>>= 8;
  x[i+2] = u; u >>>= 8;
  x[i+3] = u;
}

function ROTATE(v, c) {
  return (v << c) | (v >>> (32 - c));
}

var Chacha20 = function(key, nonce, counter) {
  this.input = new Uint32Array(16);

  // https://tools.ietf.org/html/draft-irtf-cfrg-chacha20-poly1305-01#section-2.3
  this.input[0] = 1634760805;
  this.input[1] =  857760878;
  this.input[2] = 2036477234;
  this.input[3] = 1797285236;
  this.input[4] = U8TO32_LE(key, 0);
  this.input[5] = U8TO32_LE(key, 4);
  this.input[6] = U8TO32_LE(key, 8);
  this.input[7] = U8TO32_LE(key, 12);
  this.input[8] = U8TO32_LE(key, 16);
  this.input[9] = U8TO32_LE(key, 20);
  this.input[10] = U8TO32_LE(key, 24);
  this.input[11] = U8TO32_LE(key, 28);
  this.input[12] = counter;
  this.input[13] = U8TO32_LE(nonce, 0);
  this.input[14] = U8TO32_LE(nonce, 4);
  this.input[15] = U8TO32_LE(nonce, 8);
};

Chacha20.prototype.quarterRound = function(x, a, b, c, d) {
  x[a] += x[b]; x[d] = ROTATE(x[d] ^ x[a], 16);
  x[c] += x[d]; x[b] = ROTATE(x[b] ^ x[c], 12);
  x[a] += x[b]; x[d] = ROTATE(x[d] ^ x[a],  8);
  x[c] += x[d]; x[b] = ROTATE(x[b] ^ x[c],  7);
};

Chacha20.prototype.encrypt = function(dst, src, len) {
  var x = new Uint32Array(16);
  var output = new Uint8Array(64);
  var i, dpos = 0, spos = 0;

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
    for (i = 16; i--;) U32TO8_LE(output, 4*i, x[i]);

    this.input[12] += 1;
    if (!this.input[12]) {
      this.input[13] += 1;
    }
    if (len <= 64) {
      for (i = len; i--;) {
        dst[i+dpos] = src[i+spos] ^ output[i];
      }
      return;
    }
    for (i = 64; i--;) {
      dst[i+dpos] = src[i+spos] ^ output[i];
    }
    len -= 64;
    spos += 64;
    dpos += 64;
  }
};

Chacha20.prototype.keystream = function(dst, len) {
  for (var i = 0; i < len; ++i) dst[i] = 0;
  this.encrypt(dst, dst, len);
};

/* poly1305 */
 
// Written in 2014 by Devi Mandiri. Public domain.
//
// Implementation derived from poly1305-donna-16.h
// See for details: https://github.com/floodyberry/poly1305-donna
 
var Poly1305KeySize = 32;
var Poly1305TagSize = 16;
 
var Poly1305 = function(key) {
  this.buffer = new Uint8Array(16);
  this.leftover = 0;
  this.r = new Uint16Array(10);
  this.h = new Uint16Array(10);
  this.pad = new Uint16Array(8);
  this.finished = 0;

  var t = new Uint16Array(8), i;
 
  for (i = 8; i--;) t[i] = U8TO16_LE(key, i*2);
 
  this.r[0] =   t[0]                         & 0x1fff;
  this.r[1] = ((t[0] >>> 13) | (t[1] <<  3)) & 0x1fff;
  this.r[2] = ((t[1] >>> 10) | (t[2] <<  6)) & 0x1f03;
  this.r[3] = ((t[2] >>>  7) | (t[3] <<  9)) & 0x1fff;
  this.r[4] = ((t[3] >>>  4) | (t[4] << 12)) & 0x00ff;
  this.r[5] =  (t[4] >>>  1)                 & 0x1ffe;
  this.r[6] = ((t[4] >>> 14) | (t[5] <<  2)) & 0x1fff;
  this.r[7] = ((t[5] >>> 11) | (t[6] <<  5)) & 0x1f81;
  this.r[8] = ((t[6] >>>  8) | (t[7] <<  8)) & 0x1fff;
  this.r[9] =  (t[7] >>>  5)                 & 0x007f;
 
  for (i = 8; i--;) {
    this.h[i]   = 0;
    this.pad[i] = U8TO16_LE(key, 16+(2*i));
  }
  this.h[8] = 0;
  this.h[9] = 0;
  this.leftover = 0;
  this.finished = 0;  
};

function U8TO16_LE(p, pos) {
  return (p[pos] & 0xff) | ((p[pos+1] & 0xff) << 8);
}
 
function U16TO8_LE(p, pos, v) {
  p[pos]   = v;
  p[pos+1] = v >>> 8;
}

Poly1305.prototype.blocks = function(m, mpos, bytes) {
  var hibit = this.finished ? 0 : (1 << 11);
  var t = new Uint16Array(8),
      d = new Uint32Array(10),
      c = 0, i = 0, j = 0;
 
  while (bytes >= 16) {
    for (i = 8; i--;) t[i] = U8TO16_LE(m, i*2+mpos);
 
    this.h[0] +=   t[0]                         & 0x1fff;
    this.h[1] += ((t[0] >>> 13) | (t[1] <<  3)) & 0x1fff;
    this.h[2] += ((t[1] >>> 10) | (t[2] <<  6)) & 0x1fff;
    this.h[3] += ((t[2] >>>  7) | (t[3] <<  9)) & 0x1fff;
    this.h[4] += ((t[3] >>>  4) | (t[4] << 12)) & 0x1fff;
    this.h[5] +=  (t[4] >>>  1)                 & 0x1fff;
    this.h[6] += ((t[4] >>> 14) | (t[5] <<  2)) & 0x1fff;
    this.h[7] += ((t[5] >>> 11) | (t[6] <<  5)) & 0x1fff;
    this.h[8] += ((t[6] >>>  8) | (t[7] <<  8)) & 0x1fff;
    this.h[9] +=  (t[7] >>>  5)                 | hibit;
 
    for (i = 0, c = 0; i < 10; i++) {
      d[i] = c;
      for (j = 0; j < 10; j++) {
        d[i] += (this.h[j] & 0xffffffff) * ((j <= i) ? this.r[i-j] : (5 * this.r[i+10-j]));
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
 
    for (i = 10; i--;) this.h[i] = d[i];
 
    mpos += 16;
    bytes -= 16;
  }
};

Poly1305.prototype.update = function(m, bytes) {
  var want = 0, i = 0, mpos = 0;
 
  if (this.leftover) {
    want = 16 - this.leftover;
    if (want > bytes)
      want = bytes;
    for (i = want; i--;) {
      this.buffer[this.leftover+i] = m[i+mpos];
    }
    bytes -= want;
    mpos += want;
    this.leftover += want;
    if (this.leftover < 16)
      return;
    this.blocks(this.buffer, 0, 16);
    this.leftover = 0;    
  }
 
  if (bytes >= 16) {
    want = (bytes & ~(16 - 1));
    this.blocks(m, mpos, want);
    mpos += want;
    bytes -= want;
  }
 
  if (bytes) {
    for (i = bytes; i--;) {
      this.buffer[this.leftover+i] = m[i+mpos];
    }
    this.leftover += bytes;
  }
};
 
Poly1305.prototype.finish = function() {
  var mac = new Uint8Array(16),
      g = new Uint16Array(10),
      c = 0, mask = 0, f = 0, i = 0;
 
  if (this.leftover) {
    i = this.leftover;
    this.buffer[i++] = 1;
    for (; i < 16; i++) {
      this.buffer[i] = 0;
    }
    this.finished = 1;
    this.blocks(this.buffer, 0, 16);
  }
 
  c = this.h[1] >>> 13;
  this.h[1] &= 0x1fff;
  for (i = 2; i < 10; i++) {
    this.h[i] += c;
    c = this.h[i] >>> 13;
    this.h[i] &= 0x1fff;
  }
  this.h[0] += (c * 5);
  c = this.h[0] >>> 13;
  this.h[0] &= 0x1fff;
  this.h[1] += c;
  c = this.h[1] >>> 13;
  this.h[1] &= 0x1fff;
  this.h[2] += c;
 
  g[0] = this.h[0] + 5;
  c = g[0] >>> 13;
  g[0] &= 0x1fff;
  for (i = 1; i < 10; i++) {
    g[i] = this.h[i] + c;
    c = g[i] >>> 13;
    g[i] &= 0x1fff;
  }
  g[9] -= (1 << 13);
 
  mask = (g[9] >>> 15) - 1;
  for (i = 10; i--;) g[i] &= mask;
  mask = ~mask;
  for (i = 10; i--;) {
    this.h[i] = (this.h[i] & mask) | g[i];
  }
 
  this.h[0] = (this.h[0]      ) | (this.h[1] << 13);
  this.h[1] = (this.h[1] >>  3) | (this.h[2] << 10);
  this.h[2] = (this.h[2] >>  6) | (this.h[3] <<  7);
  this.h[3] = (this.h[3] >>  9) | (this.h[4] <<  4);
  this.h[4] = (this.h[4] >> 12) | (this.h[5] <<  1) | (this.h[6] << 14);
  this.h[5] = (this.h[6] >>  2) | (this.h[7] << 11);
  this.h[6] = (this.h[7] >>  5) | (this.h[8] <<  8);
  this.h[7] = (this.h[8] >>  8) | (this.h[9] <<  5);
 
  f = (this.h[0] & 0xffffffff) + this.pad[0];
  this.h[0] = f;
  for (i = 1; i < 8; i++) {
    f = (this.h[i] & 0xffffffff) + this.pad[i] + (f >>> 16);
    this.h[i] = f;
  }
 
  for (i = 8; i--;) {
    U16TO8_LE(mac, i*2, this.h[i]);
    this.pad[i] = 0;
  }
  for (i = 10; i--;) {
    this.h[i] = 0;
    this.r[i] = 0;
  }

  return mac;
};

function poly1305_auth(m, bytes, key) {
  var ctx = new Poly1305(key);
  ctx.update(m, bytes);
  return ctx.finish();
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

function store64(dst, num) {
  var hi = 0, lo = num >>> 0;
  if ((+(Math.abs(num))) >= 1) {
    if (num > 0) {
      hi = ((Math.min((+(Math.floor(num/4294967296))), 4294967295))|0) >>> 0;
    } else {
      hi = (~~((+(Math.ceil((num - +(((~~(num)))>>>0))/4294967296))))) >>> 0;
    }
  }
  dst.push(lo & 0xff); lo >>>= 8;
  dst.push(lo & 0xff); lo >>>= 8;
  dst.push(lo & 0xff); lo >>>= 8;
  dst.push(lo & 0xff);
  dst.push(hi & 0xff); hi >>>= 8;
  dst.push(hi & 0xff); hi >>>= 8;
  dst.push(hi & 0xff); hi >>>= 8;
  dst.push(hi & 0xff);
}

function aead_mac(polykey, data, ciphertext) {
  var dlen = data.length,
      clen = ciphertext.length,
      dpad = dlen % 16,
      cpad = clen % 16,
      m = Array.apply([], data), i;

  if (dpad !== 0) {
    for (i = (16 - dpad); i--;) m.push(0);
  }

  m = m.concat(Array.apply([], ciphertext));

  if (cpad !== 0) {
    for (i = (16 - cpad); i--;) m.push(0);
  }

  store64(m, dlen);
  store64(m, clen);

  return poly1305_auth(m, m.length, polykey);
}

function aead_encrypt(key, nonce, plaintext, data) {
  var plen = plaintext.length,
      buf = new Uint8Array(plen),
      ciphertext = new Uint8Array(plen),
      polykey = new Uint8Array(64),
      ctx = new Chacha20(key, nonce, 0);

  ctx.keystream(polykey, 64);

  ctx.keystream(buf, plen);

  for (var i = 0; i < plen; i++) {
    ciphertext[i] = buf[i] ^ plaintext[i];
  }

  return [ciphertext, aead_mac(polykey, data, ciphertext)];
}

function aead_decrypt(key, nonce, ciphertext, data, mac) {
  var plen = ciphertext.length,
      buf = new Uint8Array(plen),
      plaintext = new Uint8Array(plen),
      polykey = new Uint8Array(64),
      ctx = new Chacha20(key, nonce, 0);

  ctx.keystream(polykey, 64);

  var tag = aead_mac(polykey, data, ciphertext);

  if (poly1305_verify(tag, mac) !== 1) return false;

  ctx.keystream(buf, plen);

  for (var i = 0; i < plen; i++) {
    plaintext[i] = buf[i] ^ ciphertext[i];
  }

  return plaintext;
}

//--------------------------- test -----------------------------//
function fromHex(h) {
  h = h.replace(/([^0-9a-f])/g, '');
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

function printHex(num, len, padlen, block) {
  var ret = '', pad = '', i;
  for (i=0; i<padlen;i++) pad += '0';
  i = 0;
  while (i < len) {
    var h = num[i].toString(16);
    ret += (pad + h).slice(-padlen);
    ret += ((i%block) === block-1) ? '\n' : ' ';
    i++;
  }
  console.log(ret);
}

function decodeUTF8(s) {
  var i, d = unescape(encodeURIComponent(s)), b = new Uint8Array(d.length);
  for (i = 0; i < d.length; i++) b[i] = d.charCodeAt(i);
  return b;
}

function chacha20_block_test() {
  console.log('chacha20 block test');
  var testVectors = [
    {
      key:      '00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f',
      nonce:    '00:00:00:09:00:00:00:4a:00:00:00:00',
      counter:  1,
      expected: '10 f1 e7 e4 d1 3b 59 15 50 0f dd 1f a3 20 71 c4'+
                'c7 d1 f4 c7 33 c0 68 03 04 22 aa 9a c3 d4 6c 4e'+
                'd2 82 64 46 07 9f aa 09 14 c2 d7 05 d9 8b 02 a2'+
                'b5 12 9c d1 de 16 4e b9 cb d0 83 e8 a2 50 3c 4e'
    },
    {
      key:      '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'+
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
      nonce:    '00 00 00 00 00 00 00 00 00 00 00 00',
      counter:  1,
      expected: '9f 07 e7 be 55 51 38 7a 98 ba 97 7c 73 2d 08 0d'+
                'cb 0f 29 a0 48 e3 65 69 12 c6 53 3e 32 ee 7a ed'+
                '29 b7 21 76 9c e6 4e 43 d5 71 33 b0 74 d8 39 d5'+
                '31 ed 1f 28 51 0a fb 45 ac e1 0a 1f 4b 79 4d 6f'
    },
    {
      key:      '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'+
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01',
      nonce:    '00 00 00 00 00 00 00 00 00 00 00 00',
      counter:  1,
      expected: '3a eb 52 24 ec f8 49 92 9b 9d 82 8d b1 ce d4 dd'+
                '83 20 25 e8 01 8b 81 60 b8 22 84 f3 c9 49 aa 5a'+
                '8e ca 00 bb b4 a7 3b da d1 92 b5 c4 2f 73 f2 fd'+
                '4e 27 36 44 c8 b3 61 25 a6 4a dd eb 00 6c 13 a0'
    },
    {
      key:      '00 ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00'+
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
      nonce:    '00 00 00 00 00 00 00 00 00 00 00 00',
      counter:  2,
      expected: '72 d5 4d fb f1 2e c4 4b 36 26 92 df 94 13 7f 32'+
                '8f ea 8d a7 39 90 26 5e c1 bb be a1 ae 9a f0 ca'+
                '13 b2 5a a2 6c b4 a6 48 cb 9b 9d 1b e6 5b 2c 09'+
                '24 a6 6c 54 d5 45 ec 1b 73 74 f4 87 2e 99 f0 96'
    },
    {
      key:      '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'+
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
      nonce:    '00 00 00 00 00 00 00 00 00 00 00 02',
      counter:  0,
      expected: 'c2 c6 4d 37 8c d5 36 37 4a e2 04 b9 ef 93 3f cd'+
                '1a 8b 22 88 b3 df a4 96 72 ab 76 5b 54 ee 27 c7'+
                '8a 97 0e 0e 95 5c 14 f3 a8 8e 74 1b 97 c2 86 f7'+
                '5f 8f c2 99 e8 14 83 62 fa 19 8a 39 53 1b ed 6d'
    }
  ];

  for (var i = 0; i < testVectors.length; i++) {
    var key = fromHex(testVectors[i].key),
        nonce = fromHex(testVectors[i].nonce),
        counter = testVectors[i].counter,
        expected = fromHex(testVectors[i].expected),
        len = expected.length,
        output = new Uint8Array(len);

    var ctx = new Chacha20(key, nonce, counter);

    ctx.keystream(output, len);

    if (bytesEqual(output, expected) !== 1) {
      console.log(i, 'ERROR');
    } else {
      console.log(i, 'OK');
    }
  }
}

function chacha20_encryption_test() {
  console.log('chacha20 encryption test');
  var testVectors = [
    {
      key:       '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'+
                 '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
      nonce:     '00 00 00 00 00 00 00 00 00 00 00 00',
      counter:   0,
      plaintext: '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'+
                 '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'+
                 '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'+
                 '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
      expected:  '76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28'+
                 'bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7'+
                 'da 41 59 7c 51 57 48 8d 77 24 e0 3f b8 d8 4a 37'+
                 '6a 43 b8 f4 15 18 a1 1c c3 87 b6 69 b2 ee 65 86'
    },
    {
      key:       '00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f',
      nonce:     '00:00:00:00:00:00:00:4a:00:00:00:00',
      counter:   1,
      plaintext: '4c 61 64 69 65 73 20 61 6e 64 20 47 65 6e 74 6c'+
                 '65 6d 65 6e 20 6f 66 20 74 68 65 20 63 6c 61 73'+
                 '73 20 6f 66 20 27 39 39 3a 20 49 66 20 49 20 63'+
                 '6f 75 6c 64 20 6f 66 66 65 72 20 79 6f 75 20 6f'+
                 '6e 6c 79 20 6f 6e 65 20 74 69 70 20 66 6f 72 20'+
                 '74 68 65 20 66 75 74 75 72 65 2c 20 73 75 6e 73'+
                 '63 72 65 65 6e 20 77 6f 75 6c 64 20 62 65 20 69'+
                 '74 2e',
      expected:  '6e 2e 35 9a 25 68 f9 80 41 ba 07 28 dd 0d 69 81'+
                 'e9 7e 7a ec 1d 43 60 c2 0a 27 af cc fd 9f ae 0b'+
                 'f9 1b 65 c5 52 47 33 ab 8f 59 3d ab cd 62 b3 57'+
                 '16 39 d6 24 e6 51 52 ab 8f 53 0c 35 9f 08 61 d8'+
                 '07 ca 0d bf 50 0d 6a 61 56 a3 8e 08 8a 22 b6 5e'+
                 '52 bc 51 4d 16 cc f8 06 81 8c e9 1a b7 79 37 36'+
                 '5a f9 0b bf 74 a3 5b e6 b4 0b 8e ed f2 78 5e 42'+
                 '87 4d'
    },
    {
      key:       '1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0'+
                 '47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0',
      nonce:     '00 00 00 00 00 00 00 00 00 00 00 02',
      counter:   42,
      plaintext: '27 54 77 61 73 20 62 72 69 6c 6c 69 67 2c 20 61'+
                 '6e 64 20 74 68 65 20 73 6c 69 74 68 79 20 74 6f'+
                 '76 65 73 0a 44 69 64 20 67 79 72 65 20 61 6e 64'+
                 '20 67 69 6d 62 6c 65 20 69 6e 20 74 68 65 20 77'+
                 '61 62 65 3a 0a 41 6c 6c 20 6d 69 6d 73 79 20 77'+
                 '65 72 65 20 74 68 65 20 62 6f 72 6f 67 6f 76 65'+
                 '73 2c 0a 41 6e 64 20 74 68 65 20 6d 6f 6d 65 20'+
                 '72 61 74 68 73 20 6f 75 74 67 72 61 62 65 2e',
      expected:  '62 e6 34 7f 95 ed 87 a4 5f fa e7 42 6f 27 a1 df'+
                 '5f b6 91 10 04 4c 0d 73 11 8e ff a9 5b 01 e5 cf'+
                 '16 6d 3d f2 d7 21 ca f9 b2 1e 5f b1 4c 61 68 71'+
                 'fd 84 c5 4f 9d 65 b2 83 19 6c 7f e4 f6 05 53 eb'+
                 'f3 9c 64 02 c4 22 34 e3 2a 35 6b 3e 76 43 12 a6'+
                 '1a 55 32 05 57 16 ea d6 96 25 68 f8 7d 3f 3f 77'+
                 '04 c6 a8 d1 bc d1 bf 4d 50 d6 15 4b 6d a7 31 b1'+
                 '87 b5 8d fd 72 8a fa 36 75 7a 79 7a c1 88 d1'
    },
  ];

  for (var i = 0; i < testVectors.length; i++) {
    var key = fromHex(testVectors[i].key),
        nonce = fromHex(testVectors[i].nonce),
        counter = testVectors[i].counter,
        plaintext = fromHex(testVectors[i].plaintext),
        expected = fromHex(testVectors[i].expected),
        len = plaintext.length,
        buf = new Uint8Array(len),
        output = new Uint8Array(len);

    var ctx = new Chacha20(key, nonce, counter);

    ctx.keystream(buf, len);

    for (var j = 0; j < len; j++) {
      output[j] = buf[j] ^ plaintext[j];
    }

    if (bytesEqual(output, expected) !== 1) {
      console.log(i, 'ERROR');
    } else {
      console.log(i, 'OK');
    }
  }
}

function poly1305_test() {
  console.log('poly1305 test');
  var testVectors = [
    {
      input: '27 54 77 61 73 20 62 72 69 6c 6c 69 67 2c 20 61'+
             '6e 64 20 74 68 65 20 73 6c 69 74 68 79 20 74 6f'+
             '76 65 73 0a 44 69 64 20 67 79 72 65 20 61 6e 64'+
             '20 67 69 6d 62 6c 65 20 69 6e 20 74 68 65 20 77'+
             '61 62 65 3a 0a 41 6c 6c 20 6d 69 6d 73 79 20 77'+
             '65 72 65 20 74 68 65 20 62 6f 72 6f 67 6f 76 65'+
             '73 2c 0a 41 6e 64 20 74 68 65 20 6d 6f 6d 65 20'+
             '72 61 74 68 73 20 6f 75 74 67 72 61 62 65 2e',
      key:   '1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0'+
             '47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0',
      tag:   '45 41 66 9a 7e aa ee 61 e7 08 dc 7c bc c5 eb 62'
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

    var out = poly1305_auth(input, input.length, key);

    if (poly1305_verify(expected, out) !== 1) {
      console.log('error: ', i);
      console.log('want:\n', expected.join(' '));
      console.log('got :\n', out.join(' '), '\n');  
    } else {
      console.log(i, 'OK');
    }
  }
}

function aead_test1() {
  console.log('aead test1');
  var testVectors = [
    {
      key:        '80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f'+
                  '90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f',
      nonce:      '07 00 00 00 40 41 42 43 44 45 46 47',
      plaintext:  '4c 61 64 69 65 73 20 61 6e 64 20 47 65 6e 74 6c'+
                  '65 6d 65 6e 20 6f 66 20 74 68 65 20 63 6c 61 73'+
                  '73 20 6f 66 20 27 39 39 3a 20 49 66 20 49 20 63'+
                  '6f 75 6c 64 20 6f 66 66 65 72 20 79 6f 75 20 6f'+
                  '6e 6c 79 20 6f 6e 65 20 74 69 70 20 66 6f 72 20'+
                  '74 68 65 20 66 75 74 75 72 65 2c 20 73 75 6e 73'+
                  '63 72 65 65 6e 20 77 6f 75 6c 64 20 62 65 20 69'+
                  '74 2e',
      aad:        '50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7',
      ciphertext: 'd3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2'+
                  'a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6'+
                  '3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b'+
                  '1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36'+
                  '92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58'+
                  'fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc'+
                  '3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b'+
                  '61 16',
      tag:        '1a:e1:0b:59:4f:09:e2:6a:7e:90:2e:cb:d0:60:06:91'
    }
  ];

  for (var i = 0; i < testVectors.length; i++) {
    var key = fromHex(testVectors[i].key),
        nonce = fromHex(testVectors[i].nonce),
        plaintext = fromHex(testVectors[i].plaintext),
        aad = fromHex(testVectors[i].aad),
        ciphertext = fromHex(testVectors[i].ciphertext),
        tag = fromHex(testVectors[i].tag);

    var ret = aead_encrypt(key, nonce, plaintext, aad);

    if ((bytesEqual(ret[0], ciphertext) !== 1) || (bytesEqual(ret[1], tag) !== 1)) {
      console.log(i, 'encryption error');
      console.log('want:');
      printHex(ciphertext, ciphertext.length, 2, 16);
      console.log('got:');
      printHex(ret[0], ret[0].length, 2, 16);
    } else {
      console.log(i, 'encryption OK');
    }

    ret = aead_decrypt(key, nonce, ret[0], aad, ret[1]);

    if (ret === false) {
      console.log(i, 'decryption error');
      continue;
    }

    if (bytesEqual(ret, plaintext) !== 1) {
      console.log(i, 'decryption error');
      console.log('want:');
      printHex(plaintext, plaintext.length, 2, 16);
      console.log('got:');
      printHex(ret, ret.length, 2, 16);
    } else {
      console.log(i, 'decryption OK');
    }
  }
}

function aead_test2() {
  console.log('aead test2');
  var testVectors = [
    {
      key:        '1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0'+
                  '47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0',
      nonce:      '00 00 00 00 01 02 03 04 05 06 07 08',
      plaintext:  'Internet-Drafts are draft documents valid for a maximum of six months and may be updated, replaced, or obsoleted by other documents at any time. It is inappropriate to use Internet-Drafts as reference material or to cite them other than as /“work in progress./”',
      aad:        'f3 33 88 86 00 00 00 00 00 00 4e 91',
      ciphertext: '64 a0 86 15 75 86 1a f4 60 f0 62 c7 9b e6 43 bd'+
                  '5e 80 5c fd 34 5c f3 89 f1 08 67 0a c7 6c 8c b2'+
                  '4c 6c fc 18 75 5d 43 ee a0 9e e9 4e 38 2d 26 b0'+
                  'bd b7 b7 3c 32 1b 01 00 d4 f0 3b 7f 35 58 94 cf'+
                  '33 2f 83 0e 71 0b 97 ce 98 c8 a8 4a bd 0b 94 81'+
                  '14 ad 17 6e 00 8d 33 bd 60 f9 82 b1 ff 37 c8 55'+
                  '97 97 a0 6e f4 f0 ef 61 c1 86 32 4e 2b 35 06 38'+
                  '36 06 90 7b 6a 7c 02 b0 f9 f6 15 7b 53 c8 67 e4'+
                  'b9 16 6c 76 7b 80 4d 46 a5 9b 52 16 cd e7 a4 e9'+
                  '90 40 c5 a4 04 33 22 5e e2 82 a1 b0 a0 6c 52 3e'+
                  'af 45 34 d7 f8 3f a1 15 5b 00 47 71 8c bc 54 6a'+
                  '0d 07 2b 04 b3 56 4e ea 1b 42 22 73 f5 48 27 1a'+
                  '0b b2 31 60 53 fa 76 99 19 55 eb d6 31 59 43 4e'+
                  'ce bb 4e 46 6d ae 5a 10 73 a6 72 76 27 09 7a 10'+
                  '49 e6 17 d9 1d 36 10 94 fa 68 f0 ff 77 98 71 30'+
                  '30 5b ea ba 2e da 04 df 99 7b 71 4d 6c 6f 2c 29'+
                  'a6 ad 5c b4 02 2b 02 70 9b',
      tag:        'ee ad 9d 67 89 0c bb 22 39 23 36 fe a1 85 1f 38'
    }
  ];

  for (var i = 0; i < testVectors.length; i++) {
    var key = fromHex(testVectors[i].key),
        nonce = fromHex(testVectors[i].nonce),
        plaintext = decodeUTF8(testVectors[i].plaintext),
        aad = fromHex(testVectors[i].aad),
        ciphertext = fromHex(testVectors[i].ciphertext),
        tag = fromHex(testVectors[i].tag);

    var ret = aead_encrypt(key, nonce, plaintext, aad);

    if ((bytesEqual(ret[0], ciphertext) !== 1) || (bytesEqual(ret[1], tag) !== 1)) {
      console.log(i, 'encryption error');
      console.log('want:');
      printHex(ciphertext, ciphertext.length, 2, 16);
      console.log('got:');
      printHex(ret[0], ret[0].length, 2, 16);
    } else {
      console.log(i, 'encryption OK');
    }

    ret = aead_decrypt(key, nonce, ret[0], aad, ret[1]);

    if (ret === false) {
      console.log(i, 'decryption error');
      continue;
    }

    if (bytesEqual(ret, plaintext) !== 1) {
      console.log(i, 'decryption error');
      console.log('want:');
      printHex(plaintext, plaintext.length, 2, 16);
      console.log('got:');
      printHex(ret, ret.length, 2, 16);
    } else {
      console.log(i, 'decryption OK');
    }
  }
}

chacha20_block_test();
chacha20_encryption_test();
poly1305_test();
aead_test1()
aead_test2()
