import { Link, Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { useI18n } from '../../shared/i18n/I18nProvider';
import { useThemeMode } from '../../shared/theme/ThemeProvider';
import { Button } from '../../shared/ui/Button';
import { defaultProtectedPath, protectedRoutes } from '../routes';

export function AppLayout({ session, onLogout }) {
  const location = useLocation();
  const { locale, setLocale, t } = useI18n();
  const { mode, setMode } = useThemeMode();
  const activeRoute = protectedRoutes.find((route) => location.pathname.startsWith(route.path));

  return (
    <div className="app-shell">
      <aside className="sidebar page-transition">
        <Link to={defaultProtectedPath} className="brand-lockup" aria-label={t('app.brand')}>
          <span className="brand-mark" aria-hidden="true">
            <span />
            <span />
            <span />
          </span>
          <span>
            <strong>{t('app.brand')}</strong>
            <small>{t('app.subtitle')}</small>
          </span>
        </Link>

        <nav className="side-nav" aria-label="Primary navigation">
          {protectedRoutes.map((route) => {
            const active = location.pathname.startsWith(route.path);
            return (
              <Link key={route.path} to={route.path} className={active ? 'active' : ''}>
                <span className="nav-glyph" aria-hidden="true" />
                {t(route.labelKey)}
              </Link>
            );
          })}
        </nav>

        <div className="sidebar-footer">
          <label>
            <span>{t('theme.system')}</span>
            <select value={mode} onChange={(event) => setMode(event.target.value)}>
              <option value="system">{t('theme.system')}</option>
              <option value="light">{t('theme.light')}</option>
              <option value="dark">{t('theme.dark')}</option>
            </select>
          </label>
          <label>
            <span>{locale === 'zh-CN' ? t('locale.zh') : t('locale.en')}</span>
            <select value={locale} onChange={(event) => setLocale(event.target.value)}>
              <option value="zh-CN">{t('locale.zh')}</option>
              <option value="en-US">{t('locale.en')}</option>
            </select>
          </label>
        </div>
      </aside>

      <div className="main-shell">
        <header className="topbar page-transition">
          <div className="topbar-identity">
            <h2>{activeRoute ? t(activeRoute.labelKey) : t('app.brand')}</h2>
            <small>{t('app.signedInAs', { username: session.username })}</small>
          </div>
          <Button variant="secondary" onClick={onLogout}>{t('app.logout')}</Button>
        </header>

        <main className="page-body">
          <Routes>
            <Route path="/" element={<Navigate to={defaultProtectedPath} replace />} />
            {protectedRoutes.map((route) => (
              <Route key={route.path} path={route.path} element={route.element} />
            ))}
            <Route path="/users" element={<Navigate to={defaultProtectedPath} replace />} />
            <Route path="/clients" element={<Navigate to={defaultProtectedPath} replace />} />
            <Route path="/security" element={<Navigate to={defaultProtectedPath} replace />} />
            <Route path="/app-access" element={<Navigate to={defaultProtectedPath} replace />} />
            <Route path="/tools" element={<Navigate to={defaultProtectedPath} replace />} />
            <Route path="*" element={<Navigate to={defaultProtectedPath} replace />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}
