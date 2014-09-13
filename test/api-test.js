var assert = require('assert');
var crypto = require('crypto');
var ecdsa = require('../');

var key = require('fs').readFileSync(__dirname + '/keys/key.pem');

describe('raw-ecdsa', function() {
  it('should sign/verify data', function() {
    var priv = new ecdsa.Key(key);

    var hash = crypto.createHash('sha1').update('hello world').digest();
    var s = priv.sign(hash);
    assert(priv.verify(s, hash));

    var hash2 = crypto.createHash('sha1').update('hello world2').digest();
    var s2 = priv.sign(hash2);
    assert(!priv.verify(s, hash2));
  });
});
