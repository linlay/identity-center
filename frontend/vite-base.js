const DEFAULT_ADMIN_BASE_PATH = '/admin/';

export function normalizeViteBasePath(value) {
  const raw = typeof value === 'string' ? value.trim() : '';
  if (raw === '') {
    return DEFAULT_ADMIN_BASE_PATH;
  }

  const normalizedSlashes = raw.replace(/\\/g, '/');
  if (/^[A-Za-z]:\//u.test(normalizedSlashes)) {
    throw new Error(
      'VITE_BASE_PATH was converted to a Windows filesystem path. Disable MSYS path conversion and use /admin/.'
    );
  }

  if (/^https?:\/\//iu.test(normalizedSlashes)) {
    return normalizedSlashes.endsWith('/') ? normalizedSlashes : `${normalizedSlashes}/`;
  }

  if (!normalizedSlashes.startsWith('/')) {
    throw new Error('VITE_BASE_PATH must be an absolute URL path beginning with /.');
  }

  return normalizedSlashes.endsWith('/') ? normalizedSlashes : `${normalizedSlashes}/`;
}
