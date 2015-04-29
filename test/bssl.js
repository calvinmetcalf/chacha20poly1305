var fixtures = require('./fixtures.json');
var test = require('tape');
var chacha = require('../').AeadLegacy;

fixtures.forEach(function (fixture, i) {
  // if ((new Buffer(fixture.TAG, 'hex')).length !== 16) {
  //   return;
  // }
  test('fixture ' + i, function (t) {
    t.plan(3);

    var key = new Buffer(fixture.KEY, 'hex');
    var nonce = new Buffer(fixture.NONCE, 'hex');
    var plain = new Buffer(fixture.IN, 'hex');
    var ad = new Buffer(fixture.AD, 'hex');
    var ciphertext = new Buffer(fixture.CT, 'hex');
    var tag = new Buffer(fixture.TAG, 'hex');

    var cipher = new chacha(key, nonce);
    if (ad.length) {
      cipher.setAAD(ad);
    }
    var output = cipher.update(plain);
    t.equals(output.toString('hex'), ciphertext.toString('hex'), 'encypt it correctly');
    cipher.final();
    var atag = cipher.getAuthTag();
    var outTag = cipher.getAuthTag();
    t.equals(outTag.slice(0, tag.length).toString('hex'), tag.toString('hex'), 'correct tag');
    var decipher = new chacha(key, nonce, true);
    if (ad.length) {
      decipher.setAAD(ad);
    }
    var poutput = decipher.update(ciphertext);
    t.equals(poutput.toString('hex'), plain.toString('hex'), 'deencypt it correctly');
  });
});
