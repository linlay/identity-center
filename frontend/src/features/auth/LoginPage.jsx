import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { request } from '../../shared/api/apiClient';
import { useAsyncAction } from '../../shared/hooks/useAsyncAction';
import { useI18n } from '../../shared/i18n/I18nProvider';
import { Button } from '../../shared/ui/Button';
import { PageCard } from '../../shared/ui/PageCard';
import { toast } from '../../shared/ui/toast';
import { defaultProtectedPath } from '../../app/routes';

export function LoginPage({ onLogin }) {
  const navigate = useNavigate();
  const { t } = useI18n();
  const { loading, error, setError, run } = useAsyncAction();
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('password');

  const submit = async (event) => {
    event.preventDefault();

    try {
      const session = await run(async () => {
        return request('/session/login', {
          method: 'POST',
          skipAuthRedirect: true,
          body: JSON.stringify({ username, password })
        });
      });

      onLogin(session);
      navigate(defaultProtectedPath);
      toast.success(t('login.success'));
    } catch {
      toast.error(t('login.failed'));
    }
  };

  return (
    <div className="auth-center">
      <PageCard title={t('login.title')} className="login-card">
        {error ? <div className="error">{error}</div> : null}
        <form onSubmit={submit}>
          <label>{t('login.username')}</label>
          <input
            value={username}
            onChange={(event) => {
              setUsername(event.target.value);
              setError('');
            }}
            required
          />

          <label>{t('login.password')}</label>
          <input
            type="password"
            value={password}
            onChange={(event) => {
              setPassword(event.target.value);
              setError('');
            }}
            required
          />

          <Button type="submit" loading={loading}>{t('login.submit')}</Button>
        </form>
      </PageCard>
    </div>
  );
}
