const crypto = require('crypto');

/**
 * Scrypt-based password hashing with unique random salt (Argon2/bcrypt-class security)
 * Format: scrypt$<salt_hex>$<derived_key_hex>
 */
function hashPassword(password) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16).toString('hex');
    crypto.scrypt(password, salt, 64, { N: 16384, r: 8, p: 1 }, (err, derivedKey) => {
      if (err) return reject(err);
      resolve(`scrypt$${salt}$${derivedKey.toString('hex')}`);
    });
  });
}

function verifyPassword(password, storedHash) {
  return new Promise((resolve) => {
    if (!storedHash || typeof storedHash !== 'string') return resolve(false);

    // Support existing seed hashes or plain transition passwords safely
    if (!storedHash.startsWith('scrypt$')) {
      const match = (password === storedHash);
      return resolve(match);
    }

    const parts = storedHash.split('$');
    if (parts.length !== 3) return resolve(false);

    const salt = parts[1];
    const originalHash = parts[2];

    crypto.scrypt(password, salt, 64, { N: 16384, r: 8, p: 1 }, (err, derivedKey) => {
      if (err) return resolve(false);
      try {
        const keyBuffer = Buffer.from(derivedKey.toString('hex'), 'hex');
        const origBuffer = Buffer.from(originalHash, 'hex');
        if (keyBuffer.length !== origBuffer.length) return resolve(false);
        resolve(crypto.timingSafeEqual(keyBuffer, origBuffer));
      } catch {
        resolve(false);
      }
    });
  });
}

function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

module.exports = {
  hashPassword,
  verifyPassword,
  generateSessionToken
};
