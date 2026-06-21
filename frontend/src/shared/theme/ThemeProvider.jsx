import { createContext, useContext, useEffect, useMemo, useState } from 'react';

const STORAGE_KEY = 'identity-center.theme';
const themeModes = ['system', 'light', 'dark'];

const ThemeContext = createContext({
  mode: 'system',
  resolvedTheme: 'light',
  setMode: () => {}
});

function readStoredMode() {
  const stored = localStorage.getItem(STORAGE_KEY);
  return themeModes.includes(stored) ? stored : 'system';
}

function resolveTheme(mode) {
  if (mode === 'light' || mode === 'dark') {
    return mode;
  }
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

export function ThemeProvider({ children }) {
  const [mode, setModeState] = useState(readStoredMode);
  const [resolvedTheme, setResolvedTheme] = useState(() => resolveTheme(mode));

  const setMode = (nextMode) => {
    const normalized = themeModes.includes(nextMode) ? nextMode : 'system';
    localStorage.setItem(STORAGE_KEY, normalized);
    setModeState(normalized);
  };

  useEffect(() => {
    const media = window.matchMedia('(prefers-color-scheme: dark)');
    const apply = () => {
      const nextTheme = resolveTheme(mode);
      setResolvedTheme(nextTheme);
      document.documentElement.dataset.theme = nextTheme;
      document.documentElement.dataset.themeMode = mode;
    };
    apply();
    media.addEventListener('change', apply);
    return () => media.removeEventListener('change', apply);
  }, [mode]);

  const value = useMemo(() => ({ mode, resolvedTheme, setMode }), [mode, resolvedTheme]);
  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useThemeMode() {
  return useContext(ThemeContext);
}
