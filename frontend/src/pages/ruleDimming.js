import { isRetiredUpstream } from './sigmaRulesTable';

export function isRuleDimmed(rule) {
  return rule?.is_active === false || isRetiredUpstream(rule);
}
