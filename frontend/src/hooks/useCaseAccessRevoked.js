import { createElement, Fragment, useRef } from 'react';
import { Link, matchPath, useLocation, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useSocketEvent } from './useSocket';
import { useToast, LONG_DURATION } from '../components/ui/Toast';
import {
  caseNameOf,
  currentUserId,
  handleCaseAccessRevoked,
  saveChatDraft,
  setAccessNotice,
} from '../utils/caseAccess';

export function useCaseAccessRevoked(socket, { onRevoked } = {}) {
  const { t } = useTranslation();
  const { toast } = useToast();
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const pathRef = useRef(pathname);
  pathRef.current = pathname;

  useSocketEvent(socket, 'case:access:revoked', (payload) => {
    const currentCaseId = matchPath({ path: '/cases/:id', end: false }, pathRef.current)?.params.id ?? null;
    if (onRevoked && currentCaseId && String(payload?.case_id || '').toLowerCase() === currentCaseId.toLowerCase()) {
      onRevoked(currentCaseId);
    }
    return handleCaseAccessRevoked(payload, {
      currentCaseId,
      userId: currentUserId(),
      navigate,
      saveNotice: setAccessNotice,
      saveDraft: saveChatDraft,
      caseName: caseNameOf,
      notify: (kind, key, vars, { listLink } = {}) => {
        const text = t(key, vars);
        const message = listLink
          ? createElement(Fragment, null, text, ' ', createElement(Link, { to: '/cases', className: 'fl-link' }, t('casedetail.access_revoked_list_link')))
          : text;
        toast[kind](message, LONG_DURATION);
      },
      now: () => Date.now(),
    });
  });
}
