var fixtures = require('./fixtures.json');
console.log(fixtures.length);
var test = require('tape');
var chacha = require('../legacy-aead');

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
    t.equals(output.toString('hex'), ciphertext.toString('hex'), 'encrypt it correctly');
    cipher.final();
    var atag = cipher.getAuthTag();
    var outTag = cipher.getAuthTag();
    t.equals(outTag.slice(0, tag.length).toString('hex'), tag.toString('hex'), 'correct tag');
    var decipher = new chacha(key, nonce, true);
    if (ad.length) {
      decipher.setAAD(ad);
    }
    var poutput = decipher.update(new Buffer(fixture.CT, 'hex'));
    t.equals(poutput.toString('hex'), (new Buffer(fixture.IN, 'hex')).toString('hex'), 'decrypt it correctly');
  });
});