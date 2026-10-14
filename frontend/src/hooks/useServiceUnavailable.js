import { useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { useToast, LONG_DURATION } from '../components/ui/Toast';
import { SERVICE_UNAVAILABLE_EVENT } from '../utils/api';

export function useServiceUnavailable() {
  const { t } = useTranslation();
  const { toast } = useToast();
  useEffect(() => {
    const onUnavailable = () => toast.warn(t('common.service_unavailable'), LONG_DURATION);
    window.addEventListener(SERVICE_UNAVAILABLE_EVENT, onUnavailable);
    return () => window.removeEventListener(SERVICE_UNAVAILABLE_EVENT, onUnavailable);
  }, [toast, t]);
}
