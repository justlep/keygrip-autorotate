/*!
 * keygrip-autorotate
 * Copyright(c) 2018 Lennart Pegel
 * MIT Licensed
 */

'use strict';

const assert = require('assert');
const crypto = require('crypto');
const Keygrip = require('keygrip');

const DESTROYED_ERROR_MSG = 'KeygripAutorotate instance is already destroyed';

/**
 * A key-signing and signature-verification helper based on Keygrip ({@link https://github.com/crypto-utils/keygrip}),
 * extended with internal auto-rotation of secrets used for signing, so any previously used secret is discarded
 * automatically after a maximum TTL.
 *
 * Signing is always done using the freshest of the secret only.
 *
 * @param {object} opts
 * @param {number} opts.totalSecrets - the number of secrets to use for signing and verification
 * @param {number} opts.ttlPerSecret - the maximum time to live per secret in millis, from its creation till being rotated out
 * @param {function} [opts.createSecret] - a function returning a new secret.
 *                                       If omitted, secrets are auto-generated as 32 random byte hex strings
 * @param {string} [opts.hmacAlgorithm] - defaults to 'sha256' (alternative 'sha1')
 * @param {string} [opts.encoding] - defaults to 'base64' (alternative 'hex', ...)
 *
 * @constructor
 */
function KeygripAutorotate(opts) {
    if (!this instanceof KeygripAutorotate) {
        throw new Error('KeygripAutorotate is a constructor');
    }

    assert(opts && typeof opts === 'object', 'invalid options');

    const {totalSecrets, ttlPerSecret, hmacAlgorithm = 'sha256', createSecret = _defaultCreateSecret, encoding = 'base64'} = opts;

    assert(!isNaN(totalSecrets) && totalSecrets >= 2,'totalSecrets should be > 2');
    assert(!isNaN(ttlPerSecret) && ttlPerSecret >= 1000, 'ttlPerSecret should be greater than 1000 (millis)');
    assert(hmacAlgorithm && typeof hmacAlgorithm === 'string', 'hmacAlgorithm must be a valid hmac algorithm or omitted');
    assert(encoding && typeof encoding === 'string', 'Invalid encoding');
    assert(typeof createSecret === 'function', 'createSecret must be a secret-generating function');
    const rotationInterval = Math.round(ttlPerSecret / totalSecrets);
    assert(rotationInterval < Math.pow(2,31), 'Secret rotation intervals over 24 days are not supported');

    const secrets = Array(totalSecrets).fill(null).map(createSecret);
    const keygrip = new Keygrip(secrets, hmacAlgorithm, encoding);

    let isDestroyed = false;

    /**
     * @type {Object} - the interval Timeout object while {@link periodicSecretRotate} gets called periodically.
     *                  A falsy value of `rotationTimer` means
     *                    - secrets rotation is currently paused, and
     *                    - none of the current secrets has been used for signing anything yet
     */
    let rotationTimer;

    let rotationsTillPause = 0;

    const periodicSecretRotate = function() {
        if (!rotationsTillPause) {
            rotationTimer = void(clearInterval(rotationTimer));
            return;
        }

        secrets.pop();
        secrets.unshift(createSecret());

        --rotationsTillPause;
    };

    /**
     * @param {string|Buffer} data
     * @return {string} a signature for data, calculated using the freshest secret
     */
    this.sign = function(data) {
        if (isDestroyed) {
            throw new Error(DESTROYED_ERROR_MSG);
        }
        rotationsTillPause = totalSecrets;
        if (!rotationTimer) {
            rotationTimer = setInterval(periodicSecretRotate, rotationInterval);
        }
        return keygrip.sign(data);
    };

    /**
     * @see https://github.com/crypto-utils/keygrip
     * @param {string|Buffer} data
     * @param {string} digest
     * @return {number} - the index of the matched secret
     */
    this.index = (data, digest) => {
        if (isDestroyed) {
            throw new Error(DESTROYED_ERROR_MSG);
        }
        return keygrip.index(data, digest);
    };

    /**
     * Verifies if the given digest was generated with any of the current secrets.
     *
     * (!) If {@link rotationTimer} is currently falsy, we know beforehand that *none* of the current secrets
     *     can have been used for signing. Let's call verify nonetheless, so the outside world can't determine
     *     the current status of rotation just through timings.
     *
     * @see https://github.com/crypto-utils/keygrip
     * @param {string|Buffer} data
     * @param {string} digest
     * @return {boolean} - true if the digest was generated with of the secrets, otherwise false
     */
    this.verify = (data, digest) => {
        if (isDestroyed) {
            throw new Error(DESTROYED_ERROR_MSG);
        }
        return keygrip.verify(data, digest) && !!rotationTimer; // ignore result if all secrets are unused
    };


    /**
     * Marks this instances destroyed and stops any running interval timer, e.g. to let the process exit without delays.
     * Subsequent calls of any other methods will throw an error.
     */
    this.destroy = function() {
        isDestroyed = true;
        if (rotationTimer) {
            rotationTimer = void(clearInterval(rotationTimer));
        }
    };
}

/**
 * @return {string}
 * @private
 */
function _defaultCreateSecret() {
    return crypto.randomBytes(32).toString('hex');
}


module.exports = KeygripAutorotate;