# keygrip-autorotate [![Build Status](https://api.travis-ci.com/justlep/keygrip-autorotate.svg?branch=master)](https://travis-ci.com/justlep/keygrip-autorotate)  [![NPM Version][npm-image]][npm-url] [![Node.js Version][node-version-image]][node-version-url]

Key signing and verification with periodically auto-rotating secrets.

Basically a wrapper around [Keygrip](https://github.com/crypto-utils/keygrip), 
but with fully isolated, internal handling of the secrets (keys) array. 
`KeygripAutorotate` periodically rotates a new secret in and old one out, 
so every secret used for signature-generation has a limited time to live. 

## Installation
```shell
$ npm i --save keygrip-autorotate
```

## Usage
```javascript
import {KeygripAutorotate} from 'keygrip-autorotate';

const grip = new KeygripAutorotate({
    totalSecrets: 6, 
    ttlPerSecret: 6*60*1000, // 6 minutes 
    createSecret: () => crypto.randomBytes(32).toString('hex'), // default
    hmacAlgorithm: 'sha256' // default
});


let signature = grip.sign('hello');
assert(grip.verify('hello', signature)); // ok
assert.equal(grip.sign('hello'), signature); // same secret used

// TTL 6 minutes means: a secret is used for signature-creation 
// only for about 1 minute (6 minutes / 6 total secrets)
// After 60 secs, a fresh new secret is rotated in, and the "oldest" one rotated out

// ** wait 61 seconds.. **

// The secret used to calculate `signature` is still in the bunch,
// so the old signature can be verified
assert(grip.verify('hello', signature)); // OK
let sig2 = grip.sign('world');

// Re-calculating the signature leads to a different hash
// since a new secret has taken the place of the `freshest`,
// and only the freshest is used for signature-creation. 
assert.notEqual(grip.sign('hello'), signature);

// ** wait another 5 minutes.. **

// the secret used for `signature` got rotated out, 
// so `signature` can no longer be verified
assert(!grip.verify('hello', signature));

// the secret of `sig2` is currently at the "oldest" position,
// so `sig2` can still be verified 
assert(grip.verify('world', sig2));

// a minute later, the above verify will fail

```

## Constructor
`new KeygripAutorotate(options)`

* `totalSecrets`: Number - how many secrets are held concurrently  
  (while signing is always done using the freshest key in the bunch only)
* `ttlPerSecret`: Number - the maximum duration from the first time a secret is used 
  for generating a signature, and the point when it finally gets rotated out
* (optional) `createSecret`: Function - an optional function that returns fresh keys.
  If omitted, secrets are auto-generated as 32 random byte hex strings.
* (optional) `hmacAlgorithm`: String - defaults to `'sha256'`
* (optional) `encoding`: String - defaults to (url-safe) `'base64'` (alternative e.g. `'hex'`)  
 

## Methods
All basically proxies to the [Keygrip](https://github.com/crypto-utils/keygrip) methods, 
except for `destroy()`, so the descriptions are copied from `Keygrip v1.0.3`. 

### sign(data)

This creates a SHA* HMAC based on the _freshest_ key in the keylist. Output depends on
HMAC algorithm and encoding. Base64 encoding results in url-safe base64 
digest (base64 without padding, replacing `+` with `-` and `/` with `_`).

* SHA1 + base64 => 27 bytes
* SHA1 + hex => 40 bytes
* SHA256 + base64 => 43 bytes
* SHA256 + hex => 64 bytes

### index(data, digest)

This loops through all of the keys currently in the keylist until the digest of the current key matches the given digest, at which point the current index is returned. If no key is matched, `-1` is returned.

The idea is that if the index returned is greater than `0`, the data should be re-signed to prevent premature credential invalidation, and enable better performance for subsequent challenges.

### verify(data, digest)

This uses `index` to return `true` if the digest matches any existing keys, and `false` otherwise.
 
### destroy()

Stops the internal secret-rotation timer (if running), so it won't block quick application shutdown.
After being called, all other method will throw an Error when called.

### Credits

* [Keygrip](https://github.com/crypto-utils/keygrip/blob/master/README.md)

### License
[MIT](LICENSE)

### Changelog

##### 1.1.0 (breaking changes)
- `KeygripAutorotate` is now ES module, requires Node 14+
- added named export

##### 1.0.0 
- initial version

[npm-image]: https://img.shields.io/npm/v/keygrip-autorotate.svg
[npm-url]: https://npmjs.org/package/keygrip-autorotate
[node-version-image]: https://img.shields.io/node/v/keygrip-autorotate.svg
[node-version-url]: https://nodejs.org/en/download/
