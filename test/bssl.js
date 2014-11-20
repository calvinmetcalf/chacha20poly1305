var fixtures = require('./fixtures.json');
console.log(fixtures.length);
var test = require('tape');
var chacha = require('../');
    var zeros = new Buffer (4);
    zeros.fill(0);
fixtures.forEach(function (fixture, i) {
  // if ((new Buffer(fixture.TAG, 'hex')).length !== 16) {
  //   return;
  // }
  test('fixture ' + i, function (t) {
    t.plan(2);

    var key = new Buffer(fixture.KEY, 'hex');
    var nonce = Buffer.concat([zeros, new Buffer(fixture.NONCE, 'hex')]);
    var plain = new Buffer(fixture.IN, 'hex');
    var ad = new Buffer(fixture.AD, 'hex');
    var ciphertext = new Buffer(fixture.CT, 'hex');
    var tag = new Buffer(fixture.TAG, 'hex');

    var cipher = chacha.createCipher(key, nonce);
    if (ad.length) {
      cipher.setAAD(ad);
    }
    var output = cipher.update(plain);
    t.equals(output.toString('hex'), ciphertext.toString('hex'), 'encypt it correctly');
    cipher.final();
    var decipher = chacha.createCipher(key, nonce);
    // if (ad.length) {
    //   cipher.setAAD(ad);
    // }
    var poutput = decipher.update(ciphertext);
    t.equals(poutput.toString('hex'), plain.toString('hex'), 'deencypt it correctly');
    //cipher.final();
    // var outTag = cipher.getAuthTag();
    // t.equals(outTag.toString('hex'), tag.toString('hex'), 'correct tag');
  });
});