import { useCallback, useEffect, useMemo, useState } from 'react';
import { getErrorMessage, isHandledUnauthorizedError, request } from '../../shared/api/apiClient';
import { useI18n } from '../../shared/i18n/I18nProvider';
import { Badge } from '../../shared/ui/Badge';
import { Button } from '../../shared/ui/Button';
import { DataTable } from '../../shared/ui/DataTable';
import { EmptyState } from '../../shared/ui/EmptyState';
import { LoadingOverlay } from '../../shared/ui/LoadingOverlay';
import { PageCard } from '../../shared/ui/PageCard';
import { toast } from '../../shared/ui/toast';
import { formatTime } from '../../shared/utils/time';

function formatBytes(value) {
  const bytes = Number(value || 0);
  if (!Number.isFinite(bytes) || bytes <= 0) {
    return '0 B';
  }
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let size = bytes;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size >= 10 || unit === 0 ? size.toFixed(0) : size.toFixed(1)} ${units[unit]}`;
}

function statusTone(status) {
  if (status === 'CONNECTED' || status === 'ACTIVE') return 'success';
  if (status === 'DISABLED' || status === 'REVOKED') return 'danger';
  return 'neutral';
}

function StatusBadge({ status }) {
  const { t } = useI18n();
  const normalized = status || 'UNKNOWN';
  return <Badge tone={statusTone(normalized)}>{t(`status.${normalized}`)}</Badge>;
}

function useTunnelList(path, fallbackMessage) {
  const { t } = useI18n();
  const [rows, setRows] = useState([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);

  const load = useCallback(async (query = '') => {
    setLoading(true);
    setError('');
    try {
      const data = await request(`${path}${query}`);
      setRows(Array.isArray(data) ? data : []);
    } catch (err) {
      const message = getErrorMessage(err, fallbackMessage || t('common.errorLoad'));
      if (!isHandledUnauthorizedError(err)) {
        setError(message);
        toast.error(message);
      }
    } finally {
      setLoading(false);
    }
  }, [fallbackMessage, path, t]);

  return { rows, setRows, error, loading, load };
}

export function TunnelOverviewPage() {
  const { t } = useI18n();
  const [bucket, setBucket] = useState('hour');
  const [data, setData] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);

  const load = useCallback(async (nextBucket = bucket) => {
    setLoading(true);
    setError('');
    try {
      const payload = await request(`/tunnel/overview?bucket=${encodeURIComponent(nextBucket)}`);
      setData(payload || {});
    } catch (err) {
      const message = getErrorMessage(err, t('common.errorLoad'));
      if (!isHandledUnauthorizedError(err)) {
        setError(message);
        toast.error(message);
      }
    } finally {
      setLoading(false);
    }
  }, [bucket, t]);

  useEffect(() => {
    load(bucket);
  }, [bucket, load]);

  const metrics = data?.metrics || {};
  const resources = data?.resources || {};
  const traffic = Array.isArray(data?.traffic) ? data.traffic : [];
  const maxTraffic = Math.max(1, ...traffic.map((point) => Number(point.totalBytes || 0)));
  const lastConnection = metrics.lastConnectionAt ? formatTime(metrics.lastConnectionAt) : t('overview.lastConnectionEmpty');

  return (
    <>
      <PageCard
        title={t('nav.overview')}
        actions={<Button variant="ghost" onClick={() => load(bucket)}>{t('overview.refresh')}</Button>}
      >
        <LoadingOverlay show={loading} label={t('overview.loading')} />
        {error ? <div className="error">{error}</div> : null}
        <div className="metric-grid">
          <div className="metric-tile">
            <span>{t('overview.activeDesktops')}</span>
            <strong>{metrics.activeDesktopConnections || 0}</strong>
          </div>
          <div className="metric-tile">
            <span>{t('overview.activeWebapps')}</span>
            <strong>{metrics.activeWebappConnections || 0}</strong>
          </div>
          <div className="metric-tile">
            <span>{t('overview.totalTraffic')}</span>
            <strong>{formatBytes(metrics.totalTrafficBytes)}</strong>
          </div>
          <div className="metric-tile">
            <span>{t('overview.lastConnection')}</span>
            <strong className="metric-time">{lastConnection}</strong>
            <small>{metrics.lastConnectionActor || metrics.lastConnectionObjectId || t('common.none')}</small>
          </div>
        </div>
      </PageCard>

      <div className="content-grid two-column">
        <PageCard title={t('overview.traffic')} actions={(
          <div className="segmented-control" role="group" aria-label={t('overview.traffic')}>
            {['hour', 'day', 'month'].map((item) => (
              <button
                key={item}
                type="button"
                className={bucket === item ? 'active' : ''}
                onClick={() => setBucket(item)}
              >
                {t(`overview.bucket.${item}`)}
              </button>
            ))}
          </div>
        )}>
          <div className="traffic-chart">
            {traffic.map((point) => {
              const desktopBytes = Number(point.desktopBytesIn || 0) + Number(point.desktopBytesOut || 0);
              const webappBytes = Number(point.webappBytesIn || 0) + Number(point.webappBytesOut || 0);
              const desktopHeight = Math.max(2, Math.round((desktopBytes / maxTraffic) * 100));
              const webappHeight = Math.max(2, Math.round((webappBytes / maxTraffic) * 100));
              return (
                <div className="traffic-bar" key={point.bucketStart} title={`${formatTime(point.bucketStart)} · ${formatBytes(point.totalBytes)}`}>
                  <span className="traffic-segment desktop" style={{ height: `${desktopHeight}%` }} />
                  <span className="traffic-segment webapp" style={{ height: `${webappHeight}%` }} />
                </div>
              );
            })}
          </div>
          <div className="chart-legend">
            <span><i className="legend-dot desktop" />{t('overview.desktopTraffic')}</span>
            <span><i className="legend-dot webapp" />{t('overview.webappTraffic')}</span>
          </div>
        </PageCard>

        <PageCard title={t('overview.resources')}>
          <div className="resource-list">
            <span>{t('overview.enabledDesktops')}<strong>{resources.enabledDesktops || 0}</strong></span>
            <span>{t('overview.disabledDesktops')}<strong>{resources.disabledDesktops || 0}</strong></span>
            <span>{t('overview.enabledWebapps')}<strong>{resources.enabledWebapps || 0}</strong></span>
            <span>{t('overview.disabledWebapps')}<strong>{resources.disabledWebapps || 0}</strong></span>
          </div>
        </PageCard>
      </div>
    </>
  );
}

export function TunnelDesktopsPage() {
  const { t } = useI18n();
  const [filters, setFilters] = useState({ q: '', status: 'ALL' });
  const [actionId, setActionId] = useState('');
  const { rows, setRows, error, loading, load } = useTunnelList('/tunnel/desktops', t('common.errorLoad'));

  const query = useMemo(() => {
    const params = new URLSearchParams();
    if (filters.q.trim()) params.set('q', filters.q.trim());
    if (filters.status !== 'ALL') params.set('status', filters.status);
    const text = params.toString();
    return text ? `?${text}` : '';
  }, [filters]);

  useEffect(() => {
    load(query);
  }, [load, query]);

  const refresh = () => load(query);
  const runDesktopAction = async (desktop, action) => {
    setActionId(`${action}:${desktop.deviceId}`);
    try {
      const result = action === 'close'
        ? await request(`/tunnel/desktops/${desktop.deviceId}/close`, { method: 'POST' })
        : await request(`/tunnel/desktops/${desktop.deviceId}`, {
          method: 'PATCH',
          body: JSON.stringify({ enabled: false })
        });
      setRows((current) => current.map((row) => (row.deviceId === result.deviceId ? result : row)));
      toast.success(action === 'close' ? t('desktops.closed') : t('desktops.disabled'));
    } catch (err) {
      const message = getErrorMessage(err, t('common.errorAction'));
      if (!isHandledUnauthorizedError(err)) {
        toast.error(message);
      }
    } finally {
      setActionId('');
    }
  };

  const columns = [
    {
      key: 'device',
      title: t('desktops.device'),
      render: (desktop) => (
        <div className="stacked-cell">
          <strong>{desktop.deviceName || desktop.deviceId}</strong>
          <small>{desktop.deviceId}</small>
          <small>{desktop.username || t('common.none')}</small>
        </div>
      )
    },
    {
      key: 'domain',
      title: t('desktops.domain'),
      render: (desktop) => (
        <div className="stacked-cell">
          <code>{desktop.publicHost}</code>
          <small>{desktop.webSocketUrl}</small>
        </div>
      )
    },
    {
      key: 'connection',
      title: t('desktops.connection'),
      render: (desktop) => (
        <div className="stacked-cell">
          <StatusBadge status={desktop.status} />
          <small>{formatTime(desktop.lastSeenAt || desktop.connectedAt)}</small>
        </div>
      )
    },
    {
      key: 'traffic',
      title: t('desktops.traffic'),
      render: (desktop) => formatBytes(Number(desktop.bytesIn || 0) + Number(desktop.bytesOut || 0))
    },
    {
      key: 'actions',
      title: t('desktops.actions'),
      render: (desktop) => (
        <div className="inline-actions">
          <Button
            variant="ghost"
            disabled={desktop.status !== 'CONNECTED' || actionId !== ''}
            loading={actionId === `close:${desktop.deviceId}`}
            onClick={() => runDesktopAction(desktop, 'close')}
          >
            {t('desktops.close')}
          </Button>
          <Button
            variant="danger"
            disabled={!desktop.enabled || actionId !== ''}
            loading={actionId === `disable:${desktop.deviceId}`}
            onClick={() => runDesktopAction(desktop, 'disable')}
          >
            {t('desktops.disable')}
          </Button>
        </div>
      )
    }
  ];

  return (
    <PageCard title={t('desktops.title')} actions={<Button variant="ghost" onClick={refresh}>{t('desktops.refresh')}</Button>}>
      <LoadingOverlay show={loading} label={t('desktops.loading')} />
      {error ? <div className="error">{error}</div> : null}
      <div className="toolbar">
        <label>
          <span>{t('desktops.search')}</span>
          <input
            value={filters.q}
            placeholder={t('desktops.searchPlaceholder')}
            onChange={(event) => setFilters((current) => ({ ...current, q: event.target.value }))}
          />
        </label>
        <label>
          <span>{t('desktops.status')}</span>
          <select
            value={filters.status}
            onChange={(event) => setFilters((current) => ({ ...current, status: event.target.value }))}
          >
            {['ALL', 'CONNECTED', 'OFFLINE', 'DISABLED'].map((status) => (
              <option key={status} value={status}>{t(`status.${status}`)}</option>
            ))}
          </select>
        </label>
      </div>
      <DataTable
        columns={columns}
        rows={rows}
        rowKey={(desktop) => desktop.deviceId}
        empty={<EmptyState title={t('desktops.emptyTitle')} description={t('desktops.emptyDesc')} />}
      />
    </PageCard>
  );
}

export function TunnelWebappsPage() {
  const { t } = useI18n();
  const [filters, setFilters] = useState({ q: '', status: 'ALL' });
  const { rows, error, loading, load } = useTunnelList('/tunnel/webapps', t('common.errorLoad'));

  const query = useMemo(() => {
    const params = new URLSearchParams();
    if (filters.q.trim()) params.set('q', filters.q.trim());
    if (filters.status !== 'ALL') params.set('status', filters.status);
    const text = params.toString();
    return text ? `?${text}` : '';
  }, [filters]);

  useEffect(() => {
    load(query);
  }, [load, query]);

  const columns = [
    {
      key: 'route',
      title: t('webapps.route'),
      render: (webapp) => (
        <div className="stacked-cell">
          <strong>{webapp.name || webapp.routeId}</strong>
          <small>{webapp.routeId}</small>
        </div>
      )
    },
    {
      key: 'domain',
      title: t('webapps.domain'),
      render: (webapp) => (
        <div className="stacked-cell">
          <code>{webapp.publicHost}</code>
          <small>{webapp.publicUrl}</small>
        </div>
      )
    },
    {
      key: 'upstream',
      title: t('webapps.upstream'),
      render: (webapp) => webapp.upstreamUrl || t('common.none')
    },
    {
      key: 'connections',
      title: t('webapps.connections'),
      render: (webapp) => (
        <div className="stacked-cell">
          <StatusBadge status={webapp.status} />
          <small>{webapp.connections || 0}</small>
        </div>
      )
    },
    {
      key: 'traffic',
      title: t('webapps.traffic'),
      render: (webapp) => formatBytes(Number(webapp.bytesIn || 0) + Number(webapp.bytesOut || 0))
    }
  ];

  return (
    <PageCard title={t('webapps.title')} actions={<Button variant="ghost" onClick={() => load(query)}>{t('webapps.refresh')}</Button>}>
      <LoadingOverlay show={loading} label={t('webapps.loading')} />
      {error ? <div className="error">{error}</div> : null}
      <div className="toolbar">
        <label>
          <span>{t('webapps.search')}</span>
          <input
            value={filters.q}
            placeholder={t('webapps.searchPlaceholder')}
            onChange={(event) => setFilters((current) => ({ ...current, q: event.target.value }))}
          />
        </label>
        <label>
          <span>{t('webapps.status')}</span>
          <select
            value={filters.status}
            onChange={(event) => setFilters((current) => ({ ...current, status: event.target.value }))}
          >
            {['ALL', 'ACTIVE', 'OFFLINE', 'DISABLED'].map((status) => (
              <option key={status} value={status}>{t(`status.${status}`)}</option>
            ))}
          </select>
        </label>
      </div>
      <DataTable
        columns={columns}
        rows={rows}
        rowKey={(webapp) => webapp.routeId}
        empty={<EmptyState title={t('webapps.emptyTitle')} description={t('webapps.emptyDesc')} />}
      />
    </PageCard>
  );
}

export function TunnelActivityPage() {
  const { t } = useI18n();
  const [filters, setFilters] = useState({ q: '', type: 'ALL', limit: 100 });
  const { rows, error, loading, load } = useTunnelList('/tunnel/activity', t('common.errorLoad'));

  const query = useMemo(() => {
    const params = new URLSearchParams();
    if (filters.q.trim()) params.set('q', filters.q.trim());
    if (filters.type !== 'ALL') params.set('type', filters.type);
    params.set('limit', String(filters.limit || 100));
    return `?${params.toString()}`;
  }, [filters]);

  useEffect(() => {
    load(query);
  }, [load, query]);

  const columns = [
    { key: 'event', title: t('activity.event'), render: (item) => <code>{item.eventType}</code> },
    { key: 'object', title: t('activity.object'), render: (item) => `${t(`type.${item.objectType}`)} · ${item.objectId}` },
    { key: 'actor', title: t('activity.actor'), render: (item) => item.actor || t('common.none') },
    { key: 'message', title: t('activity.message'), render: (item) => item.message || t('common.none') },
    { key: 'time', title: t('activity.time'), render: (item) => formatTime(item.createAt) }
  ];

  return (
    <PageCard title={t('activity.title')} actions={<Button variant="ghost" onClick={() => load(query)}>{t('activity.refresh')}</Button>}>
      <LoadingOverlay show={loading} label={t('activity.loading')} />
      {error ? <div className="error">{error}</div> : null}
      <div className="toolbar row-3">
        <label>
          <span>{t('activity.search')}</span>
          <input
            value={filters.q}
            placeholder={t('activity.searchPlaceholder')}
            onChange={(event) => setFilters((current) => ({ ...current, q: event.target.value }))}
          />
        </label>
        <label>
          <span>{t('activity.type')}</span>
          <select
            value={filters.type}
            onChange={(event) => setFilters((current) => ({ ...current, type: event.target.value }))}
          >
            {['ALL', 'desktop', 'webapp'].map((type) => (
              <option key={type} value={type}>{t(`type.${type}`)}</option>
            ))}
          </select>
        </label>
        <label>
          <span>{t('activity.limit')}</span>
          <input
            type="number"
            min="1"
            max="500"
            value={filters.limit}
            onChange={(event) => setFilters((current) => ({ ...current, limit: event.target.value }))}
          />
        </label>
      </div>
      <DataTable
        columns={columns}
        rows={rows}
        rowKey={(item) => item.activityId}
        empty={<EmptyState title={t('activity.emptyTitle')} description={t('activity.emptyDesc')} />}
      />
    </PageCard>
  );
}
