var test = require('tape');
var ciphers = require('../');
function fromHex(h, i) {
  if (i === 1) {
    return new Buffer(h);
  }
  h = h.replace(/([^0-9a-f])/g, '');
  return new Buffer(h, 'hex');
}
var testVectors = [{
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
    },
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
testVectors.forEach(function (testVector, i) {
test('stream ' + i, function (t) {
    t.plan(2);

    var key = fromHex(testVector.key),
        nonce = fromHex(testVector.nonce),
        plaintext = fromHex(testVector.plaintext, i),
        aad = fromHex(testVector.aad),
        ciphertext = fromHex(testVector.ciphertext),
        tag = fromHex(testVector.tag);
    var cipher = ciphers.createCipher(key, nonce);
    var data = [];
    cipher.on('data', function (d) {
      data.push(d);
    });
    cipher.setAAD(aad);
    cipher.write(plaintext);
    cipher.end();
    var calctag = cipher.getAuthTag();
    t.equals(calctag.toString('hex'), tag.toString('hex'));
    t.equals(Buffer.concat(data).toString('hex'), ciphertext.toString('hex'));
});
test('multi part stream ' + i, function (t) {
    t.plan(2);

    var key = fromHex(testVector.key),
        nonce = fromHex(testVector.nonce),
        plaintext = fromHex(testVector.plaintext, i),
        aad = fromHex(testVector.aad),
        ciphertext = fromHex(testVector.ciphertext),
        tag = fromHex(testVector.tag),
        mid = ~~(plaintext.length/2);
    var cipher = ciphers.createCipher(key, nonce);
    var data = [];
    cipher.on('data', function (d) {
      data.push(d);
    });
    cipher.setAAD(aad);
    cipher.write(plaintext.slice(0, mid));
    cipher.write(plaintext.slice(mid));
    cipher.end();
    var calctag = cipher.getAuthTag();
    t.equals(calctag.toString('hex'), tag.toString('hex'));
    t.equals(Buffer.concat(data).toString('hex'), ciphertext.toString('hex'));
});
test('decipher stream ' + i, function (t) {
    t.plan(1);
    var key = fromHex(testVector.key),
        nonce = fromHex(testVector.nonce),
        plaintext = fromHex(testVector.plaintext, i),
        aad = fromHex(testVector.aad),
        ciphertext = fromHex(testVector.ciphertext),
        tag = fromHex(testVector.tag);
    var cipher = ciphers.createDecipher(key, nonce);
    var data = [];
    cipher.on('data', function (d) {
      data.push(d);
    });
    cipher.setAAD(aad);
    cipher.write(ciphertext);
    cipher.setAuthTag(tag);
    cipher.end();
    t.equals(Buffer.concat(data).toString('hex'), plaintext.toString('hex'));
});
});

test('chacha stream', function (t) {
  t.plan(2);
   var testVector = {
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
    };
    var key = fromHex(testVector.key),
        nonce = fromHex(testVector.nonce),
        plaintext = fromHex(testVector.plaintext),
        ciphertext = fromHex(testVector.expected),
        mid = ~~(plaintext.length/2);
    var cipher = ciphers.chacha20(key, nonce);
    var output = cipher.update(plaintext.slice(0, mid));
    output = Buffer.concat([output, cipher.update(plaintext.slice(mid))]);
    t.notOk(cipher.final().length);
    t.equals(output.toString('hex'), ciphertext.toString('hex'));
});
test('chacha stream decipher', function (t) {
  t.plan(2);
   var testVector = {
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
    };
    var key = fromHex(testVector.key),
        nonce = fromHex(testVector.nonce),
        plaintext = fromHex(testVector.plaintext),
        ciphertext = fromHex(testVector.expected);
    var cipher = ciphers.chacha20(key, nonce);
    var output = cipher.update(ciphertext);
    t.notOk(cipher.final().length);
    t.equals(output.toString('hex'), plaintext.toString('hex'));
});
  var polyVectors = [
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
polyVectors.forEach(function (testVector, i) {
  test('polytest ' + i, function (t){
    t.plan(1);
    var input = fromHex(testVector.input);
    var key = fromHex(testVector.key);
    var expected = fromHex(testVector.tag);
    var out = ciphers.createHmac(key).update(input).digest();
    t.equals(out.toString('hex'), expected.toString('hex'));
  });
});