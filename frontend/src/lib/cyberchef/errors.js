import i18n from '../../i18n/index.js';

export class CyberChefError extends Error {
  constructor(key, params) {
    super(i18n.t(`cyberchef.${key}`, params));
    this.name = 'CyberChefError';
    this.key = key;
    this.params = params;
  }
}

export function cyberchefError(key, params) {
  return new CyberChefError(key, params);
}

export function tr(key, params) {
  return i18n.t(`cyberchef.${key}`, params);
}
