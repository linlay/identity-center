import {
  TunnelActivityPage,
  TunnelDesktopsPage,
  TunnelOverviewPage,
  TunnelWebappsPage
} from '../features/tunnel/TunnelPages';

export const protectedRoutes = [
  { path: '/overview', labelKey: 'nav.overview', element: <TunnelOverviewPage /> },
  { path: '/desktops', labelKey: 'nav.desktops', element: <TunnelDesktopsPage /> },
  { path: '/webapps', labelKey: 'nav.webapps', element: <TunnelWebappsPage /> },
  { path: '/activity', labelKey: 'nav.activity', element: <TunnelActivityPage /> }
];

export const defaultProtectedPath = '/overview';
