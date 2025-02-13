import assert from 'node:assert';
import crypto from 'node:crypto';
import {generateRandomBytes, KeygripAutorotate} from '../index.js';


describe('KeygripAutorotate', function () {

    const HEX_REGEX = /^[0-9a-f]+$/;
    const BASE64_URL_SAFE_REGEX = /^[0-9a-z_-]+$/i; // underlying keygrip is returning url-safe base64 regardless of encoding "base64" or "base64url"

    let grips = [];

    afterEach(() => {
        grips.forEach(g => g.destroy());
        grips = [];
    });

    it('should throw on invalid constructor options', function () {
        assert.throws(() => new KeygripAutorotate(), /invalid options/);
        assert.throws(() => new KeygripAutorotate({totalSecrets: null}), /totalSecrets should be/);
        assert.throws(() => new KeygripAutorotate({totalSecrets: 1}), /totalSecrets should be/);
        assert.throws(() => new KeygripAutorotate({totalSecrets: 2, ttlPerSecret: null}), /ttlPerSecret should be greater than/);
        assert.throws(() => new KeygripAutorotate({totalSecrets: 2, ttlPerSecret: 999}), /ttlPerSecret should be greater than/);
        assert.throws(() => new KeygripAutorotate({totalSecrets: 2, ttlPerSecret: Math.pow(2,31) * 2}), /Secret rotation intervals over 24 days/);

        assert.doesNotThrow(() => {
            grips.push( new KeygripAutorotate({totalSecrets: 2, ttlPerSecret: Math.pow(2,31) * 2 - 2}) );
        });
        assert.doesNotThrow(() => {
            grips.push( new KeygripAutorotate({totalSecrets: 2, ttlPerSecret: 1000}) );
        });
    });

    it('can be destroyed, thereafter throwing upon any method calls', () => {
        const grip = new KeygripAutorotate({totalSecrets: 2, ttlPerSecret: 1000, hmacAlgorithm: 'sha256', encoding: 'hex'});
        const text = 'sdfjghsdkjfdfjkghdkjfghdfugdkgghdkfjh';
        const sig = grip.sign(text);

        grip.destroy();
        assert.throws(() => grip.verify(text, sig), /KeygripAutorotate instance is already destroyed/);
        assert.throws(() => grip.index(text, sig), /KeygripAutorotate instance is already destroyed/);
        assert.throws(() => grip.sign(text), /KeygripAutorotate instance is already destroyed/);
    });

    it('should sign and verify data within one rotation cycle', () => {
        const grip = grips[grips.length] = new KeygripAutorotate({totalSecrets: 2, ttlPerSecret: 1000});
        const text = 'some text';

        let sig = grip.sign(text);
        assert(sig && BASE64_URL_SAFE_REGEX.test(sig), 'signature should be base64 string');
        assert(grip.verify(text, sig), 'the signature calculated just now should be verifiable');
        assert.equal(grip.sign(text), sig, 'the same text should produce the same signature within the current secrets rotation frame');
        assert.equal(grip.sign(text), sig, 'the same text should produce the same signature within the current secrets rotation frame');
    });

    it('supports different HMAC algorithms and signature encodings', () => {
        grips = [
            new KeygripAutorotate({totalSecrets: 2, ttlPerSecret: 1000, hmacAlgorithm: 'sha256', encoding: 'hex'}),
            new KeygripAutorotate({totalSecrets: 2, ttlPerSecret: 1000, hmacAlgorithm: 'sha256', encoding: 'base64'}),
            new KeygripAutorotate({totalSecrets: 2, ttlPerSecret: 1000, hmacAlgorithm: 'sha1', encoding: 'hex'}),
            new KeygripAutorotate({totalSecrets: 2, ttlPerSecret: 1000, hmacAlgorithm: 'sha1', encoding: 'base64'})
        ];

        let sigs = grips.map(grip => grip.sign('hello world'));

        // console.dir(sigs);

        // sha256 hex
        assert.equal(sigs[0].length, 64);
        assert(HEX_REGEX.test(sigs[0]));
        // sha256 base64
        assert.equal(sigs[1].length, 43);
        assert(BASE64_URL_SAFE_REGEX.test(sigs[1]));
        // sha1 hex
        assert.equal(sigs[2].length, 40);
        assert(HEX_REGEX.test(sigs[2]));
        // sha256 hex
        assert.equal(sigs[3].length, 27);
        assert(BASE64_URL_SAFE_REGEX.test(sigs[3]));
    });

    it('should rotate keys periodically, rendering old signatures non-verifiable', (done) => {
        const grip = grips[grips.length] = new KeygripAutorotate({totalSecrets: 2, ttlPerSecret: 1000});

        let phase1Passed,
            phase2Passed,
            phase2point5Passed,
            sig = {};

        // 2 secrets + TTL=1000ms --> rotation interval == 500ms

        // phase 1 (before first rotation of secrets)

        sig.foo = grip.sign('foo');
        setTimeout(() => {
            assert(grip.verify('foo', sig.foo), '250 millis later old secret is still at pos 0, so verification should succeed');
            assert.equal(grip.sign('foo'), sig.foo, 'freshest secret hasnt changed, so newly calculated sig should be equal to before');
            assert.equal(grip.index('foo', sig.foo), 0, 'the secret used for sig.foo is at index 0 currently');
            sig.bar = grip.sign('bar');
            phase1Passed = true;
        }, 250);

        // phase 2 (after first rotation of secrets)

        setTimeout(() => {
            assert(phase1Passed, 'previous timer hasnt finished');

            assert.equal(grip.index('foo', sig.foo), 1, 'the secret used for sig.foo got rotated to index 1');
            assert.notEqual(grip.sign('foo'), sig.foo, 'new sig for foo uses fresher secret than phase1, so the sigs should differ');
            assert(grip.verify('foo', sig.foo), 'old foo sig must be still verifiable via secret that is now at pos 1');
            assert(grip.verify('bar', sig.bar), 'previous bar sig must be still verifiable via secret that is now at pos 1');
            assert.notEqual(grip.sign('foo'), sig.foo, 'keys have rotated at ~500ms, so the sig for foo should be different now');
            assert.notEqual(grip.sign('bar'), sig.bar, 'keys have rotated at ~500ms, so the sig for foo should be different now');

            sig.baz = grip.sign('baz');
            assert.equal(grip.index('baz', sig.baz), 0, 'the secret used for sig.baz is now the freshest, at index 0');

            phase2Passed = true;
        }, 750);

        // phase 2.5 (shortly before second rotation of secrets)

        setTimeout(() => {
            assert(phase2Passed, 'previous timer hasnt finished');

            assert.equal(grip.index('baz', sig.baz), 0, 'the secret used for sig.baz is still the freshest, at index 0');
            assert.equal(grip.index('foo', sig.foo), 1, 'the secret used for sig.foo still is second at index 1');

            // begin: copy/paste from phase2
            assert.notEqual(grip.sign('foo'), sig.foo, 'new sig for foo uses fresher secret than phase1, so the sigs should differ');
            assert(grip.verify('foo', sig.foo), 'old foo sig must be still verifiable via secret that is now at pos 1');
            assert(grip.verify('bar', sig.bar), 'previous bar sig must be still verifiable via secret that is now at pos 1');
            assert.notEqual(grip.sign('foo'), sig.foo, 'keys have rotated at ~500ms, so the sig for foo should be different now');
            assert.notEqual(grip.sign('bar'), sig.bar, 'keys have rotated at ~500ms, so the sig for foo should be different now');
            // end: copy/paste from phase2

            assert(grip.verify('baz', sig.baz), 'sig.baz was generated in same phase 150ms before, so should be verifiable');
            assert.equal(grip.sign('baz'), sig.baz, 'secret should still be same as 150ms before, so sigs should be equal');

            phase2point5Passed = true;
        }, 900);


        // phase 3 (after second rotation -> secret from phase#1 is void & gone; phase1 signatures no longer verifiable)
        setTimeout(() => {
            assert(phase2Passed, 'previous timer hasnt finished');
            assert(phase2point5Passed, 'previous timer hasnt finished');

            assert.equal(grip.index('foo', sig.foo), -1, 'the secret used for sig.foo got rotated out, is gone');
            assert.equal(grip.index('baz', sig.baz), 1, 'the secret used for sig.baz got rotated to index 1');

            assert(!grip.verify('foo', sig.foo), 'secret for foo-sig is gone, so sig.foo should not be verifiable anymore');
            assert.notEqual(grip.sign('foo'), sig.foo, 'old secret of phase 1 wont come back ;)');
            assert(!grip.verify('bar', sig.bar), 'secret for foo-sig is gone, so sig.bar should not be verifiable anymore');
            assert.notEqual(grip.sign('bar'), sig.bar, 'old secret of phase 1 wont come back ;)');

            assert(grip.verify('baz', sig.baz), 'secret behind sig.baz is on pos 1, so sig.baz should be verifiable');
            assert.notEqual(grip.sign('baz'), sig.baz, 'new sig for baz used fresher secret than in phase 2, so sigs should differ');

            sig.tadaa = grip.sign('tadaa');
            assert(BASE64_URL_SAFE_REGEX.test(sig.tadaa), 'a new secret should have been inserted to sign');

            assert.equal(grip.index('foo', sig.foo), -1, 'the secret used for sig.foo is gone long ago');
            assert.equal(grip.index('bar', sig.bar), -1, 'the secret used for sig.bar got kicked after phase 2');
            assert.equal(grip.index('baz', sig.baz), 1, 'the secret used for sig.baz is second. some fresher secret took its place');
            assert.equal(grip.index('tadaa', sig.tadaa), 0, 'the secret used for sig.tadaa now freshest');

            // retrospective format check for all signatures generated so far..
            Object.keys(sig).forEach(key => assert(BASE64_URL_SAFE_REGEX.test(sig[key]), 'format of all signs should be base64, but isnt for sig.' + key));

            done();
        }, 1250);

    });

    it('can use an external function to generate new secrets to be rotated in', (done) => {
        const FIX_SECRET = crypto.randomBytes(10);
        const HELLO = 'hello world';

        let fixSecretCreator = () => FIX_SECRET,
            randomSecretCreator = () => crypto.randomBytes(10),
            fixGrip = new KeygripAutorotate({totalSecrets: 4, ttlPerSecret: 1000, createSecret: fixSecretCreator}),
            randGrip = new KeygripAutorotate({totalSecrets: 4, ttlPerSecret: 1000, createSecret: randomSecretCreator}),
            sig = {};

        sig.fix = fixGrip.sign(HELLO);
        assert(fixGrip.verify(HELLO, sig.fix));
        sig.rand = randGrip.sign(HELLO);
        assert(randGrip.verify(HELLO, sig.rand));

        // 1000ms for 4 secrets => rotations after 250ms, 500ms, ...

        setTimeout(() => {
            assert(fixGrip.verify(HELLO, sig.fix));
            assert(randGrip.verify(HELLO, sig.rand));

            assert.equal(fixGrip.sign(HELLO), sig.fix, 'newly in-rotated secret is constant, signature remains the same');
            assert.notEqual(randGrip.sign(HELLO), sig.rand, 'in-rotated key is random, so signature must differ');

            done();
        }, 375);


        grips = [randGrip, fixGrip];
    });

    it('exports generateRandomBytes() generating variable length random byte buffers, by default 64 to 128 bytes', () => {
        let devs = 0,
            sizes = [],
            TOTAL = 5_000;

        for (let i = 0, key; i < TOTAL; i++) {
            key = generateRandomBytes();
            assert(key.length >= 64 && key.length <= 128);
            devs += (96 - key.length) * (96 - key.length);
            sizes.push(key.length);
        }
        sizes.sort((a,b) => a - b);
        assert.equal(sizes[0], 64);
        assert.equal(sizes[TOTAL - 1], 128);
        let median = sizes[TOTAL / 2];
        assert(median >= 94 && median < 98, `Expected median to be close to 96, but is ${median}`);
        let sDev = Math.sqrt(devs / (TOTAL - 1));
        assert(sDev > 18 && sDev <= 19);
    });

});
