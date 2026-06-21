import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { request } from '../../shared/api/apiClient';
import { useAsyncAction } from '../../shared/hooks/useAsyncAction';
import { Button } from '../../shared/ui/Button';
import { PageCard } from '../../shared/ui/PageCard';
import { toast } from '../../shared/ui/toast';
import { defaultProtectedPath } from '../../app/routes';

export function LoginPage({ onLogin }) {
  const navigate = useNavigate();
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
      toast.success('Signed in successfully');
    } catch {
      toast.error('Sign in failed');
    }
  };

  return (
    <div className="auth-center">
      <PageCard title="Admin Login" className="login-card">
        {error ? <div className="error">{error}</div> : null}
        <form onSubmit={submit}>
          <label>Username</label>
          <input
            value={username}
            onChange={(event) => {
              setUsername(event.target.value);
              setError('');
            }}
            required
          />

          <label>Password</label>
          <input
            type="password"
            value={password}
            onChange={(event) => {
              setPassword(event.target.value);
              setError('');
            }}
            required
          />

          <Button type="submit" loading={loading}>Sign In</Button>
        </form>
      </PageCard>
    </div>
  );
}
