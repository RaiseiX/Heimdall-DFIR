import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import fr from './fr.json';
import en from './en.json';

function getInitialLanguage() {
  try {
    const raw = localStorage.getItem('heimdall_preferences');
    if (raw) {
      const p = JSON.parse(raw);
      if (p.language === 'en' || p.language === 'fr') return p.language;
    }
  } catch {}
  return 'fr';
}

i18n
  .use(initReactI18next)
  .init({
    resources: {
      fr: { translation: fr },
      en: { translation: en },
    },
    lng: getInitialLanguage(),
    fallbackLng: 'fr',
    interpolation: { escapeValue: false },
  });

export default i18n;
