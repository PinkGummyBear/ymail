// mint.js
const crypto = require('crypto');

/**
 * @param {string} resource  e.g. "alice$yolo.com"
 * @param {number} bits      number of leading zero bits required
 * @returns {string}         a valid Hashcash stamp
 */
function mint(resource, bits) {
  const version = 1;
  const date    = new Date().toISOString().slice(2,10).replace(/-/g,'');
  const rand    = crypto.randomBytes(4).toString('hex');
  let   counter = 0;

  while (true) {
    // note: empty extension field
    const token = [version, bits, date, resource, '', rand, counter].join(':');
    const hash  = crypto.createHash('sha1').update(token).digest();

    // count leading zero bits
    let zeroBits = 0;
    for (const byte of hash) {
      if (byte === 0) { zeroBits += 8; continue; }
      for (let mask = 0x80; mask; mask >>= 1) {
        if ((byte & mask) === 0) zeroBits++;
        else break;
      }
      break;
    }

    if (zeroBits >= bits) {
      return token;
    }
    counter++;
  }
}

// export it
module.exports = { mint };
