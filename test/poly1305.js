
var Poly1305 = require('../poly1305');
var test = require('tape');
function fromHex(h) {
  h = h.replace(/([^0-9a-f])/g, '');
  return new Buffer(h, 'hex');
}

function bytesEqual(a, b, t) {
    t.equal(a.toString('hex'), b.toString('hex'));
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
function poly1305_verify(mac1, mac2, t) {
  t.equals(mac1.toString('hex'), mac2.toString('hex'));
}
function poly1305_auth(m, bytes, key) {
  var ctx = new Poly1305(key);
  ctx.update(m, bytes);
  return ctx.finish();
}
function poly1305_test() {
  test('poly1305 test', function (t) {
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

    poly1305_verify(expected, out, t);
  }
  t.end();
});
}


poly1305_test();
// aead_test1()
// aead_test2()