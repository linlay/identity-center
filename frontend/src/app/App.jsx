import { useEffect, useRef } from 'react';
import { Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom';
import { LoginPage } from '../features/auth/LoginPage';
import { getErrorMessage, isHandledUnauthorizedError, request, subscribeUnauthorized } from '../shared/api/apiClient';
import { useAuthSession } from '../shared/hooks/useAuthSession';
import { useI18n } from '../shared/i18n/I18nProvider';
import { LoadingOverlay } from '../shared/ui/LoadingOverlay';
import { ToastViewport } from '../shared/ui/ToastViewport';
import { toast } from '../shared/ui/toast';
import { AppLayout } from './layout/AppLayout';
import { defaultProtectedPath } from './routes';

export default function App() {
  const navigate = useNavigate();
  const location = useLocation();
  const { loading, session, setSession } = useAuthSession();
  const { t } = useI18n();
  const unauthorizedRedirectingRef = useRef(false);

  const logout = async () => {
    try {
      await request('/session/logout', { method: 'POST' });
      setSession(null);
      navigate('/login');
      toast.success(t('app.signedOut'));
    } catch (err) {
      if (!isHandledUnauthorizedError(err)) {
        toast.error(getErrorMessage(err, t('app.signOutFailed')));
      }
    }
  };

  useEffect(() => {
    return subscribeUnauthorized(() => {
      if (unauthorizedRedirectingRef.current) {
        return;
      }
      unauthorizedRedirectingRef.current = true;
      setSession(null);
      if (location.pathname !== '/login') {
        toast.error(t('app.sessionExpired'));
      }
      navigate('/login', { replace: true });
    });
  }, [location.pathname, navigate, setSession, t]);

  useEffect(() => {
    if (location.pathname === '/login') {
      unauthorizedRedirectingRef.current = false;
    }
  }, [location.pathname]);

  if (loading) {
    return (
      <>
        <LoadingOverlay show label={t('app.loadingSession')} />
        <ToastViewport />
      </>
    );
  }

  return (
    <>
      <Routes>
        <Route
          path="/login"
          element={session ? <Navigate to={defaultProtectedPath} replace /> : <LoginPage onLogin={setSession} />}
        />
        <Route
          path="/*"
          element={session ? <AppLayout session={session} onLogout={logout} /> : <Navigate to="/login" replace />}
        />
      </Routes>
      <ToastViewport />
    </>
  );
}
