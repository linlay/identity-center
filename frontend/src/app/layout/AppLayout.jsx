import { Link, Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { Button } from '../../shared/ui/Button';
import { defaultProtectedPath, protectedRoutes } from '../routes';

export function AppLayout({ session, onLogout }) {
  const location = useLocation();

  return (
    <div className="app-shell">
      <header className="topbar page-transition">
        <div className="topbar-identity">
          <h2>Auth Admin</h2>
          <small>Signed in as {session.username}</small>
        </div>
        <Button variant="secondary" onClick={onLogout}>Logout</Button>
      </header>

      <nav className="tabs page-transition" aria-label="Primary navigation">
        {protectedRoutes.map((route) => {
          const active = location.pathname.startsWith(route.path);
          return (
            <Link key={route.path} to={route.path} className={active ? 'active' : ''}>
              {route.label}
            </Link>
          );
        })}
      </nav>

      <main className="page-body">
        <Routes>
          {protectedRoutes.map((route) => (
            <Route key={route.path} path={route.path} element={route.element} />
          ))}
          <Route path="/users" element={<Navigate to={defaultProtectedPath} replace />} />
          <Route path="/clients" element={<Navigate to={defaultProtectedPath} replace />} />
          <Route path="*" element={<Navigate to={defaultProtectedPath} replace />} />
        </Routes>
      </main>
    </div>
  );
}
