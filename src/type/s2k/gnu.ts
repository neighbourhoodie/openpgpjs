import defaultConfig from '../../config';
import crypto from '../../crypto';
import { UnsupportedError } from '../../packet/packet';
import util from '../../util';

class GnuS2K {
  type: string;
  c: number;
  salt: Uint8Array | null;
  /**
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   */
  constructor(config = defaultConfig) {
    /**
     * @type {String}
     */
    this.type = 'gnu'
    /** @type {Integer} */
    this.c = config.s2kIterationCountByte;
    /** Eight bytes of salt in a binary string.
     * @type {Uint8Array}
     */
    this.salt = null;
  }

  /**
   * Parsing function for a string-to-key specifier ({@link https://tools.ietf.org/html/rfc4880#section-3.7|RFC 4880 3.7}).
   * @param {Uint8Array} bytes - Payload of string-to-key specifier
   * @returns {Integer} Actual length of the object.
   */
  read(bytes: Uint8Array): Number {
    let i = 0;
    
    if (util.uint8ArrayToString(bytes.subarray(i, i + 3)) === 'GNU') {
      i += 3;
      const gnuExtType = 1000 + bytes[i++];
      if (gnuExtType === 1001) {
        this.type = 'gnu-dummy';
        // GnuPG extension mode 1001 -- don't write secret key at all
      } else {
        throw new UnsupportedError('Unknown s2k gnu protection mode.');
      }
    } else {
      throw new UnsupportedError('Unknown s2k type.');
    }

    return i;
  }

  /**
   * Serializes s2k information
   * @returns {Uint8Array} Binary representation of s2k.
   */
  write(): Uint8Array {
    if (this.type === 'gnu-dummy') {
      return new Uint8Array([101, 0, ...util.stringToUint8Array('GNU'), 1]);
    }

    throw new Error('GNU s2k type not supported.');
  }

  /**
   * Produces a key using the specified passphrase and the defined
   * hashAlgorithm
   * @param {String} passphrase - Passphrase containing user input
   * @returns {Promise<Uint8Array>} Produced key with a length corresponding to.
   * hashAlgorithm hash length
   * @async
   */
  async produceKey(passphrase: string, numBytes: number): Promise<Uint8Array> {
    throw new Error('GNU s2k type not supported.');
  }
}

export default GnuS2K;
