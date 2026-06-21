import { useEffect, useState } from 'react';
import { getErrorMessage, isHandledUnauthorizedError, request } from '../../shared/api/apiClient';
import { copyToClipboard } from '../../shared/utils/clipboard';
import { formatTime } from '../../shared/utils/time';
import { Badge } from '../../shared/ui/Badge';
import { Button } from '../../shared/ui/Button';
import { LoadingOverlay } from '../../shared/ui/LoadingOverlay';
import { PageCard } from '../../shared/ui/PageCard';
import { toast } from '../../shared/ui/toast';

const ACCESS_TTL_MAX_SECONDS = 30 * 24 * 60 * 60;
const createDefaultAccessTtl = () => ({ days: '0', hours: '0', minutes: '10', seconds: '0' });
const createInitialIssueForm = () => ({
  masterPassword: 'password',
  deviceName: 'Admin Console Device',
  accessTtl: createDefaultAccessTtl()
});
const createInitialRefreshForm = () => ({
  deviceToken: '',
  accessTtl: createDefaultAccessTtl()
});

function normalizePart(value, label) {
  const text = String(value ?? '').trim();
  if (!text) {
    return 0;
  }
  if (!/^\d+$/.test(text)) {
    throw new Error(`${label} must be a non-negative integer`);
  }
  return Number(text);
}

function accessTtlToSeconds(parts) {
  const days = normalizePart(parts.days, 'Days');
  const hours = normalizePart(parts.hours, 'Hours');
  const minutes = normalizePart(parts.minutes, 'Minutes');
  const seconds = normalizePart(parts.seconds, 'Seconds');
  const total = days * 86400 + hours * 3600 + minutes * 60 + seconds;

  if (total < 1) {
    throw new Error('Access TTL must be at least 1 second');
  }
  if (total > ACCESS_TTL_MAX_SECONDS) {
    throw new Error(`Access TTL must be <= ${ACCESS_TTL_MAX_SECONDS} seconds (30 days)`);
  }
  return total;
}

export function SecurityPage() {
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const [jwks, setJwks] = useState(null);
  const [generatedPublicKey, setGeneratedPublicKey] = useState('');
  const [issueForm, setIssueForm] = useState(createInitialIssueForm);
  const [refreshForm, setRefreshForm] = useState(createInitialRefreshForm);

  const [issueResult, setIssueResult] = useState(null);
  const [refreshResult, setRefreshResult] = useState(null);
  const [newDeviceAccess, setNewDeviceAccess] = useState(false);
  const [updatingNewDeviceAccess, setUpdatingNewDeviceAccess] = useState(false);
  const [loading, setLoading] = useState(true);

  const copyText = async (text) => {
    if (await copyToClipboard(text)) {
      setSuccess('Copied to clipboard');
      toast.success('Copied to clipboard');
    } else {
      setError('Failed to copy to clipboard');
      toast.error('Failed to copy to clipboard');
    }
  };

  const loadJwks = async () => {
    const data = await request('/security/jwks');
    setJwks(data);
  };

  const loadNewDeviceAccess = async () => {
    const data = await request('/security/new-device-access');
    setNewDeviceAccess(Boolean(data?.allowNewDeviceLogin));
  };

  const loadAll = async () => {
    setLoading(true);
    setError('');
    try {
      await Promise.all([loadJwks(), loadNewDeviceAccess()]);
    } catch (err) {
      const message = getErrorMessage(err, 'Failed to load security data');
      if (!isHandledUnauthorizedError(err)) {
        setError(message);
        toast.error(message);
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAll();
  }, []);

  const issueAppToken = async (event) => {
    event.preventDefault();
    setError('');
    setSuccess('');

    try {
      const payload = {
        masterPassword: issueForm.masterPassword,
        deviceName: issueForm.deviceName,
        accessTtlSeconds: accessTtlToSeconds(issueForm.accessTtl)
      };
      const result = await request('/security/app-tokens/issue', {
        method: 'POST',
        body: JSON.stringify(payload)
      });
      setIssueResult(result);
      setRefreshForm((prev) => ({ ...prev, deviceToken: result.deviceToken || prev.deviceToken }));
      setSuccess('Issued app access token successfully');
      toast.success('Issued app access token successfully');
    } catch (err) {
      const message = getErrorMessage(err, 'Failed to issue app token');
      if (!isHandledUnauthorizedError(err)) {
        setError(message);
        toast.error(message);
      }
    }
  };

  const refreshAppToken = async (event) => {
    event.preventDefault();
    setError('');
    setSuccess('');

    try {
      const payload = {
        deviceToken: refreshForm.deviceToken,
        accessTtlSeconds: accessTtlToSeconds(refreshForm.accessTtl)
      };
      const result = await request('/security/app-tokens/refresh', {
        method: 'POST',
        body: JSON.stringify(payload)
      });
      setRefreshResult(result);
      setRefreshForm((prev) => ({ ...prev, deviceToken: result.deviceToken || prev.deviceToken }));
      setSuccess('Refreshed app access token successfully');
      toast.success('Refreshed app access token successfully');
    } catch (err) {
      const message = getErrorMessage(err, 'Failed to refresh app token');
      if (!isHandledUnauthorizedError(err)) {
        setError(message);
        toast.error(message);
      }
    }
  };

  const generatePublicKeyFromJwkSet = async () => {
    setError('');
    setSuccess('');

    try {
      const key = jwks?.jwks?.keys?.[0];
      if (!key?.e || !key?.n) {
        throw new Error('No JWK key found');
      }
      const result = await request('/security/public-key/generate', {
        method: 'POST',
        body: JSON.stringify({ e: key.e, n: key.n })
      });
      setGeneratedPublicKey(result.publicKey || '');
      setSuccess('Generated public key successfully');
      toast.success('Generated public key successfully');
    } catch (err) {
      const message = getErrorMessage(err, 'Failed to generate public key');
      if (!isHandledUnauthorizedError(err)) {
        setError(message);
        toast.error(message);
      }
    }
  };

  const setNewDeviceAccessStatus = async (nextValue) => {
    setError('');
    setSuccess('');
    setUpdatingNewDeviceAccess(true);

    try {
      const result = await request('/security/new-device-access', {
        method: 'PUT',
        body: JSON.stringify({ allowNewDeviceLogin: nextValue })
      });
      const enabled = Boolean(result?.allowNewDeviceLogin);
      setNewDeviceAccess(enabled);
      setSuccess(`New device access ${enabled ? 'enabled' : 'disabled'}`);
      toast.success(`New device access ${enabled ? 'enabled' : 'disabled'}`);
    } catch (err) {
      const message = getErrorMessage(err, 'Failed to update new device access');
      if (!isHandledUnauthorizedError(err)) {
        setError(message);
        toast.error(message);
      }
    } finally {
      setUpdatingNewDeviceAccess(false);
    }
  };

  return (
    <>
      <PageCard title="Security Overview" actions={<Button variant="ghost" onClick={loadAll}>Refresh All</Button>}>
        <LoadingOverlay show={loading} label="Loading security data..." />
        {error ? <div className="error">{error}</div> : null}
        {success ? <div className="success">{success}</div> : null}
      </PageCard>

      <PageCard
        title="New Device Access"
        actions={<Badge tone={newDeviceAccess ? 'success' : 'danger'}>{newDeviceAccess ? 'OPEN' : 'CLOSED'}</Badge>}
      >
        <p className="muted">
          When closed, new devices cannot use <code>/api/auth/login</code> for first-time onboarding.
        </p>
        <Button
          onClick={() => setNewDeviceAccessStatus(!newDeviceAccess)}
          loading={updatingNewDeviceAccess}
        >
          {newDeviceAccess ? 'Disable New Device Access' : 'Enable New Device Access'}
        </Button>
      </PageCard>

      <PageCard title="JWKs">
        <pre className="json-block">{jwks ? JSON.stringify(jwks.jwks || {}, null, 2) : 'Loading...'}</pre>
        <div className="inline-actions spacing-top">
          <Button
            variant="secondary"
            onClick={generatePublicKeyFromJwkSet}
            disabled={!jwks?.jwks?.keys?.[0]?.e || !jwks?.jwks?.keys?.[0]?.n}
          >
            Generate Public Key
          </Button>
          {generatedPublicKey ? (
            <Button variant="ghost" onClick={() => copyText(generatedPublicKey)}>Copy Public Key</Button>
          ) : null}
        </div>
        {generatedPublicKey ? <pre className="pem-block spacing-top">{generatedPublicKey}</pre> : null}
      </PageCard>

      <PageCard title="Issue App Access Token">
        <form onSubmit={issueAppToken}>
          <div className="row row-2">
            <div>
              <label>Master Password</label>
              <input
                type="password"
                value={issueForm.masterPassword}
                onChange={(event) => setIssueForm((prev) => ({ ...prev, masterPassword: event.target.value }))}
                required
              />
            </div>
            <div>
              <label>Device Name</label>
              <input
                value={issueForm.deviceName}
                onChange={(event) => setIssueForm((prev) => ({ ...prev, deviceName: event.target.value }))}
                required
              />
            </div>
          </div>

          <div className="row row-5">
            <div>
              <label>Days</label>
              <input
                type="number"
                min="0"
                value={issueForm.accessTtl.days}
                onChange={(event) => setIssueForm((prev) => ({
                  ...prev,
                  accessTtl: { ...prev.accessTtl, days: event.target.value }
                }))}
              />
            </div>
            <div>
              <label>Hours</label>
              <input
                type="number"
                min="0"
                value={issueForm.accessTtl.hours}
                onChange={(event) => setIssueForm((prev) => ({
                  ...prev,
                  accessTtl: { ...prev.accessTtl, hours: event.target.value }
                }))}
              />
            </div>
            <div>
              <label>Minutes</label>
              <input
                type="number"
                min="0"
                value={issueForm.accessTtl.minutes}
                onChange={(event) => setIssueForm((prev) => ({
                  ...prev,
                  accessTtl: { ...prev.accessTtl, minutes: event.target.value }
                }))}
              />
            </div>
            <div>
              <label>Seconds</label>
              <input
                type="number"
                min="0"
                value={issueForm.accessTtl.seconds}
                onChange={(event) => setIssueForm((prev) => ({
                  ...prev,
                  accessTtl: { ...prev.accessTtl, seconds: event.target.value }
                }))}
              />
            </div>
            <div className="form-action-cell">
              <label className="label-spacer" aria-hidden="true">Action</label>
              <Button type="submit">Issue Token</Button>
            </div>
          </div>
          <small className="muted">Custom TTL supports days/hours/minutes/seconds. Max 30 days.</small>
        </form>

        {issueResult ? (
          <div className="card inner-card">
            <h4>Issue Result</h4>
            <table className="table compact">
              <tbody>
                <tr><th>Username</th><td>{issueResult.username}</td></tr>
                <tr><th>Device ID</th><td>{issueResult.deviceId}</td></tr>
                <tr><th>Device Name</th><td>{issueResult.deviceName}</td></tr>
                <tr><th>Expire At</th><td>{formatTime(issueResult.accessTokenExpireAt)}</td></tr>
                <tr>
                  <th>Access Token</th>
                  <td>
                    <div className="token-cell">{issueResult.accessToken}</div>
                    <Button variant="secondary" onClick={() => copyText(issueResult.accessToken)}>Copy Access Token</Button>
                  </td>
                </tr>
                <tr>
                  <th>Device Token</th>
                  <td>
                    <div className="token-cell">{issueResult.deviceToken}</div>
                    <Button variant="secondary" onClick={() => copyText(issueResult.deviceToken)}>Copy Device Token</Button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        ) : null}
      </PageCard>

      <PageCard title="Refresh App Access Token">
        <form onSubmit={refreshAppToken}>
          <div className="row row-5">
            <div>
              <label>Device Token</label>
              <input
                value={refreshForm.deviceToken}
                onChange={(event) => setRefreshForm((prev) => ({ ...prev, deviceToken: event.target.value }))}
                required
              />
            </div>
            <div>
              <label>Days</label>
              <input
                type="number"
                min="0"
                value={refreshForm.accessTtl.days}
                onChange={(event) => setRefreshForm((prev) => ({
                  ...prev,
                  accessTtl: { ...prev.accessTtl, days: event.target.value }
                }))}
              />
            </div>
            <div>
              <label>Hours</label>
              <input
                type="number"
                min="0"
                value={refreshForm.accessTtl.hours}
                onChange={(event) => setRefreshForm((prev) => ({
                  ...prev,
                  accessTtl: { ...prev.accessTtl, hours: event.target.value }
                }))}
              />
            </div>
            <div>
              <label>Minutes</label>
              <input
                type="number"
                min="0"
                value={refreshForm.accessTtl.minutes}
                onChange={(event) => setRefreshForm((prev) => ({
                  ...prev,
                  accessTtl: { ...prev.accessTtl, minutes: event.target.value }
                }))}
              />
            </div>
            <div>
              <label>Seconds</label>
              <input
                type="number"
                min="0"
                value={refreshForm.accessTtl.seconds}
                onChange={(event) => setRefreshForm((prev) => ({
                  ...prev,
                  accessTtl: { ...prev.accessTtl, seconds: event.target.value }
                }))}
              />
            </div>
          </div>
          <div className="form-action-row">
            <Button type="submit">Refresh Token</Button>
          </div>
          <small className="muted">Custom TTL supports days/hours/minutes/seconds. Max 30 days.</small>
        </form>

        {refreshResult ? (
          <div className="card inner-card">
            <h4>Refresh Result</h4>
            <table className="table compact">
              <tbody>
                <tr><th>Device ID</th><td>{refreshResult.deviceId}</td></tr>
                <tr><th>Expire At</th><td>{formatTime(refreshResult.accessTokenExpireAt)}</td></tr>
                <tr>
                  <th>Access Token</th>
                  <td>
                    <div className="token-cell">{refreshResult.accessToken}</div>
                    <Button variant="secondary" onClick={() => copyText(refreshResult.accessToken)}>Copy Access Token</Button>
                  </td>
                </tr>
                <tr>
                  <th>Device Token</th>
                  <td>
                    <div className="token-cell">{refreshResult.deviceToken}</div>
                    <Button variant="secondary" onClick={() => copyText(refreshResult.deviceToken)}>Copy Device Token</Button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        ) : null}
      </PageCard>
    </>
  );
}
