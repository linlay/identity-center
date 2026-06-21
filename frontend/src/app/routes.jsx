import { AccountsPage } from '../features/accounts/AccountsPage';
import { AppAccessPage } from '../features/access/AppAccessPage';
import { SecurityPage } from '../features/security/SecurityPage';
import { ToolsPage } from '../features/tools/ToolsPage';

export const protectedRoutes = [
  { path: '/accounts', label: 'Accounts', element: <AccountsPage /> },
  { path: '/security', label: 'Security', element: <SecurityPage /> },
  { path: '/app-access', label: 'Access', element: <AppAccessPage /> },
  { path: '/tools', label: 'Tools', element: <ToolsPage /> }
];

export const defaultProtectedPath = '/accounts';
