import Argon2S2K, { Argon2OutOfMemoryError } from './argon2';
import GenericS2K from './generic';
import enums from '../../enums';
import { UnsupportedError } from '../../packet/packet';
import GnuS2K from './gnu';

import defaultConfig from '../../config';
import { Config } from '../../../openpgp';
const allowedS2KTypesForEncryption = new Set([enums.s2k.argon2, enums.s2k.iterated]);

/**
 * Instantiate a new S2K instance of the given type
 * @param {module:enums.s2k} type
 * @param {Config} [config]
 * @returns {Object} New s2k object
 * @throws {Error} for unknown or unsupported types
 */
export function newS2KFromType (type: number, config:Config = defaultConfig ): Argon2S2K | GenericS2K | GnuS2K {
  switch (type) {
    case enums.s2k.gnu:
      return new GnuS2K();
    case enums.s2k.argon2:
      return new Argon2S2K(config);
    case enums.s2k.iterated:
    case enums.s2k.salted:
    case enums.s2k.simple:
      return new GenericS2K(type, config);
    default:
      throw new UnsupportedError('Unsupported S2K type');
  }
}

/**
 * Instantiate a new S2K instance based on the config settings
 * @param {Object} config
 * @returns {Object} New s2k object
 * @throws {Error} for unknown or unsupported types
 */
export function newS2KFromConfig(config:Config = defaultConfig) {
  const { s2kType } = config;

  if (!allowedS2KTypesForEncryption.has(s2kType)) {
    throw new Error('The provided `config.s2kType` value is not allowed');
  }

  return newS2KFromType(s2kType, config);
}

export { Argon2OutOfMemoryError };
