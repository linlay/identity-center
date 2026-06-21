import { createContext, useContext, useMemo, useState } from 'react';
import { dictionaries } from './locales';

const STORAGE_KEY = 'identity-center.locale';
const supportedLocales = ['zh-CN', 'en-US'];

const I18nContext = createContext({
  locale: 'zh-CN',
  setLocale: () => {},
  t: (key) => key
});

function resolveInitialLocale() {
  const stored = localStorage.getItem(STORAGE_KEY);
  if (supportedLocales.includes(stored)) {
    return stored;
  }
  const browserLocale = navigator.language || '';
  return browserLocale.toLowerCase().startsWith('zh') ? 'zh-CN' : 'en-US';
}

function interpolate(template, values) {
  if (!values) {
    return template;
  }
  return template.replace(/\{([a-zA-Z0-9_]+)\}/g, (_, key) => String(values[key] ?? ''));
}

export function I18nProvider({ children }) {
  const [locale, setLocaleState] = useState(resolveInitialLocale);

  const setLocale = (nextLocale) => {
    const normalized = supportedLocales.includes(nextLocale) ? nextLocale : 'zh-CN';
    localStorage.setItem(STORAGE_KEY, normalized);
    setLocaleState(normalized);
  };

  const value = useMemo(() => {
    const dictionary = dictionaries[locale] || dictionaries['zh-CN'];
    return {
      locale,
      setLocale,
      t: (key, values) => interpolate(dictionary[key] || dictionaries['en-US'][key] || key, values)
    };
  }, [locale]);

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n() {
  return useContext(I18nContext);
}
