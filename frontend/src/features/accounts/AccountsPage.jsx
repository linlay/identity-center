import { useEffect, useMemo, useState } from 'react';
import { getErrorMessage, isHandledUnauthorizedError, request } from '../../shared/api/apiClient';
import { copyToClipboard } from '../../shared/utils/clipboard';
import { Button } from '../../shared/ui/Button';
import { DataTable } from '../../shared/ui/DataTable';
import { EmptyState } from '../../shared/ui/EmptyState';
import { LoadingOverlay } from '../../shared/ui/LoadingOverlay';
import { Modal } from '../../shared/ui/Modal';
import { PageCard } from '../../shared/ui/PageCard';
import { toast } from '../../shared/ui/toast';

const initialUserForm = { username: '', password: '', displayName: '', status: 'ACTIVE' };
const initialClientForm = {
  clientId: '',
  clientName: '',
  clientSecret: '',
  grantTypes: 'authorization_code,refresh_token',
  redirectUris: 'myapp://oauthredirect',
  scopes: 'openid,profile',
  requirePkce: true,
  status: 'ACTIVE'
};

export function AccountsPage() {
  const [users, setUsers] = useState([]);
  const [clients, setClients] = useState([]);
  const [loadingUsers, setLoadingUsers] = useState(true);
  const [loadingClients, setLoadingClients] = useState(true);
  const [error, setError] = useState('');
  const [newSecret, setNewSecret] = useState('');

  const [userForm, setUserForm] = useState(initialUserForm);
  const [clientForm, setClientForm] = useState(initialClientForm);
  const [userFormError, setUserFormError] = useState('');
  const [clientFormError, setClientFormError] = useState('');
  const [userSubmitting, setUserSubmitting] = useState(false);
  const [clientSubmitting, setClientSubmitting] = useState(false);
  const [showCreateUserModal, setShowCreateUserModal] = useState(false);
  const [showCreateClientModal, setShowCreateClientModal] = useState(false);

  const parsedClientPayload = useMemo(() => ({
    clientId: clientForm.clientId,
    clientName: clientForm.clientName,
    clientSecret: clientForm.clientSecret || null,
    grantTypes: clientForm.grantTypes.split(',').map((v) => v.trim()).filter(Boolean),
    redirectUris: clientForm.redirectUris.split(',').map((v) => v.trim()).filter(Boolean),
    scopes: clientForm.scopes.split(',').map((v) => v.trim()).filter(Boolean),
    requirePkce: Boolean(clientForm.requirePkce),
    status: clientForm.status
  }), [clientForm]);

  const loadUsers = async () => {
    setLoadingUsers(true);
    try {
      const data = await request('/users');
      setUsers(Array.isArray(data) ? data : []);
    } catch (err) {
      const message = getErrorMessage(err, 'Failed to load users');
      if (!isHandledUnauthorizedError(err)) {
        setError(message);
        toast.error(message);
      }
    } finally {
      setLoadingUsers(false);
    }
  };

  const loadClients = async () => {
    setLoadingClients(true);
    try {
      const data = await request('/clients');
      setClients(Array.isArray(data) ? data : []);
    } catch (err) {
      const message = getErrorMessage(err, 'Failed to load clients');
      if (!isHandledUnauthorizedError(err)) {
        setError(message);
        toast.error(message);
      }
    } finally {
      setLoadingClients(false);
    }
  };

  const loadAll = async () => {
    setError('');
    await Promise.all([loadUsers(), loadClients()]);
  };

  useEffect(() => {
    loadAll();
  }, []);

  const createUser = async (event) => {
    event.preventDefault();
    setUserSubmitting(true);
    setUserFormError('');
    try {
      await request('/users', {
        method: 'POST',
        body: JSON.stringify(userForm)
      });
      setShowCreateUserModal(false);
      setUserForm(initialUserForm);
      toast.success('User created');
      await loadUsers();
    } catch (err) {
      const message = getErrorMessage(err, 'Failed to create user');
      if (!isHandledUnauthorizedError(err)) {
        setUserFormError(message);
        toast.error(message);
      }
    } finally {
      setUserSubmitting(false);
    }
  };

  const createClient = async (event) => {
    event.preventDefault();
    setClientSubmitting(true);
    setClientFormError('');
    try {
      await request('/clients', {
        method: 'POST',
        body: JSON.stringify(parsedClientPayload)
      });
      setShowCreateClientModal(false);
      setClientForm((prev) => ({ ...prev, clientId: '', clientName: '', clientSecret: '' }));
      toast.success('Client created');
      await loadClients();
    } catch (err) {
      const message = getErrorMessage(err, 'Failed to create client');
      if (!isHandledUnauthorizedError(err)) {
        setClientFormError(message);
        toast.error(message);
      }
    } finally {
      setClientSubmitting(false);
    }
  };

  const toggleUserStatus = async (user) => {
    const status = user.status === 'ACTIVE' ? 'DISABLED' : 'ACTIVE';
    try {
      await request(`/users/${user.userId}/status`, {
        method: 'PATCH',
        body: JSON.stringify({ status })
      });
      toast.success(`User ${status === 'ACTIVE' ? 'activated' : 'disabled'}`);
      await loadUsers();
    } catch (err) {
      const message = getErrorMessage(err, 'Failed to update user status');
      if (!isHandledUnauthorizedError(err)) {
        setError(message);
        toast.error(message);
      }
    }
  };

  const resetPassword = async (user) => {
    const password = window.prompt(`Reset password for ${user.username}`);
    if (!password) return;

    try {
      await request(`/users/${user.userId}/password`, {
        method: 'POST',
        body: JSON.stringify({ password })
      });
      toast.success('Password reset completed');
    } catch (err) {
      const message = getErrorMessage(err, 'Failed to reset password');
      if (!isHandledUnauthorizedError(err)) {
        setError(message);
        toast.error(message);
      }
    }
  };

  const unbindEmail = async (user) => {
    const reason = window.prompt(`Reason for manually unbinding ${user.username}'s email (verify ownership first)`);
    if (!reason?.trim() || !window.confirm('Unbind this email? Existing sessions remain signed in.')) return;
    try {
      await request(`/users/${user.userId}/email/unbind`, {
        method: 'POST', body: JSON.stringify({ reason: reason.trim(), confirmed: true })
      });
      toast.success('Email unbound; reason recorded');
    } catch (err) {
      if (!isHandledUnauthorizedError(err)) toast.error(getErrorMessage(err, 'Failed to unbind email'));
    }
  };

  const toggleClientStatus = async (client) => {
    const status = client.status === 'ACTIVE' ? 'DISABLED' : 'ACTIVE';
    try {
      await request(`/clients/${client.clientId}/status`, {
        method: 'PATCH',
        body: JSON.stringify({ status })
      });
      toast.success(`Client ${status === 'ACTIVE' ? 'activated' : 'disabled'}`);
      await loadClients();
    } catch (err) {
      const message = getErrorMessage(err, 'Failed to update client status');
      if (!isHandledUnauthorizedError(err)) {
        setError(message);
        toast.error(message);
      }
    }
  };

  const rotateSecret = async (client) => {
    try {
      const result = await request(`/clients/${client.clientId}/secret/rotate`, {
        method: 'POST'
      });
      setNewSecret(`${result.clientId}: ${result.newClientSecret}`);
      toast.success('Client secret rotated');
    } catch (err) {
      const message = getErrorMessage(err, 'Failed to rotate secret');
      if (!isHandledUnauthorizedError(err)) {
        setError(message);
        toast.error(message);
      }
    }
  };

  const copySecret = async () => {
    if (!newSecret) return;
    if (await copyToClipboard(newSecret)) {
      toast.success('Copied to clipboard');
      return;
    }
    toast.error('Failed to copy to clipboard');
  };

  const userColumns = useMemo(() => [
    { key: 'userId', title: 'User ID', render: (user) => user.userId },
    { key: 'username', title: 'Username', render: (user) => user.username },
    { key: 'displayName', title: 'Display Name', render: (user) => user.displayName },
    { key: 'status', title: 'Status', render: (user) => user.status },
    {
      key: 'actions',
      title: 'Actions',
      render: (user) => (
        <div className="inline-actions">
          <Button variant="secondary" onClick={() => toggleUserStatus(user)}>
            {user.status === 'ACTIVE' ? 'Disable' : 'Activate'}
          </Button>
          <Button onClick={() => resetPassword(user)}>Reset Password</Button>
          <Button variant="secondary" onClick={() => unbindEmail(user)}>Unbind Email</Button>
        </div>
      )
    }
  ], []);

  const clientColumns = useMemo(() => [
    { key: 'clientId', title: 'Client ID', render: (client) => client.clientId },
    { key: 'name', title: 'Name', render: (client) => client.clientName },
    { key: 'grantTypes', title: 'Grant Types', render: (client) => client.grantTypes.join(', ') },
    { key: 'pkce', title: 'PKCE', render: (client) => (client.requirePkce ? 'YES' : 'NO') },
    { key: 'status', title: 'Status', render: (client) => client.status },
    {
      key: 'actions',
      title: 'Actions',
      render: (client) => (
        <div className="inline-actions">
          <Button variant="secondary" onClick={() => toggleClientStatus(client)}>
            {client.status === 'ACTIVE' ? 'Disable' : 'Activate'}
          </Button>
          <Button onClick={() => rotateSecret(client)}>Rotate Secret</Button>
        </div>
      )
    }
  ], []);

  return (
    <>
      <PageCard title="Accounts" actions={<Button variant="ghost" onClick={loadAll}>Refresh All</Button>}>
        {error ? <div className="error">{error}</div> : null}
        <p className="muted compact-paragraph">
          Manage users and OAuth clients in one place. Use the create buttons to open compact dialog forms.
        </p>
      </PageCard>

      <PageCard
        title="Users"
        actions={(
          <>
            <Button variant="secondary" onClick={() => setShowCreateUserModal(true)}>Create User</Button>
            <Button variant="ghost" onClick={loadUsers}>Refresh</Button>
          </>
        )}
      >
        <LoadingOverlay show={loadingUsers} label="Loading users..." />
        <DataTable
          columns={userColumns}
          rows={users}
          rowKey={(user) => user.userId}
          empty={<EmptyState title="No users" description="Create your first user from dialog." />}
        />
      </PageCard>

      <PageCard
        title="Clients"
        actions={(
          <>
            <Button variant="secondary" onClick={() => setShowCreateClientModal(true)}>Create Client</Button>
            <Button variant="ghost" onClick={loadClients}>Refresh</Button>
          </>
        )}
      >
        <LoadingOverlay show={loadingClients} label="Loading clients..." />
        <DataTable
          columns={clientColumns}
          rows={clients}
          rowKey={(client) => client.clientId}
          empty={<EmptyState title="No clients" description="Create your first OAuth client from dialog." />}
        />
      </PageCard>

      {newSecret ? (
        <PageCard title="Rotated Client Secret" actions={<Button variant="ghost" onClick={copySecret}>Copy</Button>}>
          <pre className="mono-inline">{newSecret}</pre>
        </PageCard>
      ) : null}

      <Modal
        open={showCreateUserModal}
        title="Create User"
        onClose={() => {
          setShowCreateUserModal(false);
          setUserFormError('');
        }}
      >
        {userFormError ? <div className="error">{userFormError}</div> : null}
        <form onSubmit={createUser}>
          <div className="row row-2">
            <div>
              <label>Username</label>
              <input
                value={userForm.username}
                onChange={(event) => setUserForm((prev) => ({ ...prev, username: event.target.value }))}
                required
              />
            </div>
            <div>
              <label>Password</label>
              <input
                type="password"
                value={userForm.password}
                onChange={(event) => setUserForm((prev) => ({ ...prev, password: event.target.value }))}
                required
              />
            </div>
          </div>

          <div className="row row-2">
            <div>
              <label>Display Name</label>
              <input
                value={userForm.displayName}
                onChange={(event) => setUserForm((prev) => ({ ...prev, displayName: event.target.value }))}
                required
              />
            </div>
            <div>
              <label>Status</label>
              <select
                value={userForm.status}
                onChange={(event) => setUserForm((prev) => ({ ...prev, status: event.target.value }))}
              >
                <option value="ACTIVE">ACTIVE</option>
                <option value="DISABLED">DISABLED</option>
              </select>
            </div>
          </div>

          <div className="modal-footer">
            <Button variant="ghost" onClick={() => setShowCreateUserModal(false)}>Cancel</Button>
            <Button type="submit" loading={userSubmitting}>Create User</Button>
          </div>
        </form>
      </Modal>

      <Modal
        open={showCreateClientModal}
        title="Create Client"
        onClose={() => {
          setShowCreateClientModal(false);
          setClientFormError('');
        }}
      >
        {clientFormError ? <div className="error">{clientFormError}</div> : null}
        <form onSubmit={createClient}>
          <div className="row row-2">
            <div>
              <label>Client ID</label>
              <input
                value={clientForm.clientId}
                onChange={(event) => setClientForm((prev) => ({ ...prev, clientId: event.target.value }))}
                required
              />
            </div>
            <div>
              <label>Client Name</label>
              <input
                value={clientForm.clientName}
                onChange={(event) => setClientForm((prev) => ({ ...prev, clientName: event.target.value }))}
                required
              />
            </div>
          </div>

          <div className="row row-2">
            <div>
              <label>Client Secret (optional for public client)</label>
              <input
                value={clientForm.clientSecret}
                onChange={(event) => setClientForm((prev) => ({ ...prev, clientSecret: event.target.value }))}
              />
            </div>
            <div>
              <label>Status</label>
              <select
                value={clientForm.status}
                onChange={(event) => setClientForm((prev) => ({ ...prev, status: event.target.value }))}
              >
                <option value="ACTIVE">ACTIVE</option>
                <option value="DISABLED">DISABLED</option>
              </select>
            </div>
          </div>

          <label>Grant Types (comma separated)</label>
          <input
            value={clientForm.grantTypes}
            onChange={(event) => setClientForm((prev) => ({ ...prev, grantTypes: event.target.value }))}
          />

          <label>Redirect URIs (comma separated)</label>
          <input
            value={clientForm.redirectUris}
            onChange={(event) => setClientForm((prev) => ({ ...prev, redirectUris: event.target.value }))}
          />

          <label>Scopes (comma separated)</label>
          <input
            value={clientForm.scopes}
            onChange={(event) => setClientForm((prev) => ({ ...prev, scopes: event.target.value }))}
          />

          <label className="inline-checkbox">
            <input
              type="checkbox"
              checked={clientForm.requirePkce}
              onChange={(event) => setClientForm((prev) => ({ ...prev, requirePkce: event.target.checked }))}
            />
            Require PKCE
          </label>

          <div className="modal-footer">
            <Button variant="ghost" onClick={() => setShowCreateClientModal(false)}>Cancel</Button>
            <Button type="submit" loading={clientSubmitting}>Create Client</Button>
          </div>
        </form>
      </Modal>
    </>
  );
}
