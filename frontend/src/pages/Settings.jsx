import React, { useState } from 'react';
import { KeyRound, Plus, Trash2 } from 'lucide-react';
import { api } from '../api';
import { useSession } from '../session';
import {
  Card, CopyButton, Empty, ErrorBox, Modal, Pill, Spinner, Toggle, TypedConfirm, fmtDate, relTime, useAsync, useToast,
} from '../components/ui';

export default function Settings() {
  const { user } = useSession();
  const isAdmin = user.role === 'admin';
  const tabs = [['profile', 'Profile'], ...(isAdmin ? [['users', 'Users'], ['keys', 'API keys'], ['licence', 'Licence']] : []), ...(user.is_platform_admin ? [['tenants', 'Tenants']] : [])];
  const [tab, setTab] = useState('profile');

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Settings</h1>
          <p className="muted">{user.tenant_name} · signed in as {user.email} ({user.role})</p>
        </div>
      </div>
      <div className="tabs">
        {tabs.map(([k, label]) => <button key={k} className={tab === k ? 'on' : ''} onClick={() => setTab(k)}>{label}</button>)}
      </div>
      {tab === 'profile' && <Profile />}
      {tab === 'users' && isAdmin && <Users />}
      {tab === 'keys' && isAdmin && <ApiKeys />}
      {tab === 'tenants' && user.is_platform_admin && <Tenants />}
      {tab === 'licence' && isAdmin && <Licence />}
    </div>
  );
}

function Profile() {
  const { user, refreshUser } = useSession();
  const toast = useToast();
  const [name, setName] = useState(user.full_name || '');
  const [cur, setCur] = useState('');
  const [pw, setPw] = useState('');
  const [pw2, setPw2] = useState('');
  const [err, setErr] = useState(null);
  const [pwErr, setPwErr] = useState(null);

  const saveName = async (e) => {
    e.preventDefault();
    setErr(null);
    try {
      await api.updateMe({ full_name: name.trim() });
      await refreshUser();
      toast('Profile saved', 'ok');
    } catch (x) {
      setErr(x);
    }
  };
  const savePw = async (e) => {
    e.preventDefault();
    setPwErr(null);
    if (pw !== pw2) return setPwErr('The new passwords do not match');
    try {
      await api.updateMe({ current_password: cur, new_password: pw });
      setCur('');
      setPw('');
      setPw2('');
      toast('Password changed', 'ok');
    } catch (x) {
      setPwErr(x);
    }
    return undefined;
  };

  return (
    <div className="grid-2">
      <Card title="Profile">
        <form className="stack" onSubmit={saveName}>
          <label className="field"><span>Email</span><input className="input" value={user.email} disabled /></label>
          <label className="field"><span>Full name</span>
            <input className="input" maxLength={120} value={name} onChange={(e) => setName(e.target.value)} /></label>
          <div><button className="btn btn-primary">Save</button></div>
          <ErrorBox error={err} />
        </form>
      </Card>
      <Card title="Change password">
        <form className="stack" onSubmit={savePw}>
          <label className="field"><span>Current password</span>
            <input className="input" type="password" autoComplete="current-password" required value={cur} onChange={(e) => setCur(e.target.value)} /></label>
          <label className="field"><span>New password (min 12 characters)</span>
            <input className="input" type="password" autoComplete="new-password" required minLength={12} maxLength={256} value={pw} onChange={(e) => setPw(e.target.value)} /></label>
          <label className="field"><span>Repeat new password</span>
            <input className="input" type="password" autoComplete="new-password" required minLength={12} value={pw2} onChange={(e) => setPw2(e.target.value)} /></label>
          <div><button className="btn btn-primary">Change password</button></div>
          <ErrorBox error={pwErr} />
        </form>
      </Card>
    </div>
  );
}

function Users() {
  const { user: me } = useSession();
  const users = useAsync(() => api.users(), []);
  const toast = useToast();
  const [form, setForm] = useState({ email: '', full_name: '', password: '', role: 'analyst' });
  const [err, setErr] = useState(null);

  const create = async (e) => {
    e.preventDefault();
    setErr(null);
    try {
      const u = await api.createUser({ ...form, full_name: form.full_name || null });
      users.setData((xs) => [...(xs || []), u]);
      setForm({ email: '', full_name: '', password: '', role: 'analyst' });
      toast(`User ${u.email} created`, 'ok');
    } catch (x) {
      setErr(x);
    }
  };
  const update = async (u, patch) => {
    try {
      const nu = await api.updateUser(u.id, patch);
      users.setData((xs) => xs.map((x) => (x.id === u.id ? nu : x)));
    } catch (x) {
      toast(x.message, 'error');
    }
  };

  return (
    <>
      <Card title="Add user">
        <form className="form-inline" onSubmit={create}>
          <label className="field grow"><span>Email</span>
            <input className="input" type="email" required value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} /></label>
          <label className="field grow"><span>Full name</span>
            <input className="input" maxLength={120} value={form.full_name} onChange={(e) => setForm({ ...form, full_name: e.target.value })} /></label>
          <label className="field grow"><span>Initial password (12+)</span>
            <input className="input" type="password" autoComplete="new-password" required minLength={12} value={form.password}
              onChange={(e) => setForm({ ...form, password: e.target.value })} /></label>
          <label className="field"><span>Role</span>
            <select className="input" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
              <option value="analyst">analyst</option><option value="admin">admin</option>
            </select></label>
          <div className="field"><span>&nbsp;</span><button className="btn btn-primary"><Plus size={14} /> Add</button></div>
        </form>
        <ErrorBox error={err} />
      </Card>
      <Card title="Users">
        <ErrorBox error={users.error} onRetry={users.reload} />
        {users.loading && !users.data && <Spinner />}
        {users.data?.length > 0 && (
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Email</th><th>Name</th><th>Role</th><th>Active</th><th>Created</th></tr></thead>
              <tbody>
                {users.data.map((u) => (
                  <tr key={u.id} className={u.is_active ? '' : 'dim'}>
                    <td>{u.email} {u.id === me.id && <Pill tone="vip">you</Pill>}</td>
                    <td>{u.full_name || '—'}</td>
                    <td>
                      <select className="input input-sm" value={u.role} disabled={u.id === me.id} onChange={(e) => update(u, { role: e.target.value })}>
                        <option value="analyst">analyst</option><option value="admin">admin</option>
                      </select>
                    </td>
                    <td><Toggle checked={u.is_active} disabled={u.id === me.id} onChange={(v) => update(u, { is_active: v })} /></td>
                    <td className="nowrap">{fmtDate(u.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </>
  );
}

const SCOPES = ['ingest', 'read', 'write', 'recon'];

function ApiKeys() {
  const keys = useAsync(() => api.apiKeys(), []);
  const toast = useToast();
  const [name, setName] = useState('');
  const [scopes, setScopes] = useState(['ingest']);
  const [err, setErr] = useState(null);
  const [created, setCreated] = useState(null);

  const create = async (e) => {
    e.preventDefault();
    setErr(null);
    try {
      const k = await api.createApiKey({ name: name.trim(), scopes });
      const { key, ...rest } = k;
      keys.setData((xs) => [rest, ...(xs || [])]);
      setCreated(k);
      setName('');
      setScopes(['ingest']);
    } catch (x) {
      setErr(x);
    }
  };
  const revoke = async (k) => {
    if (!window.confirm(`Revoke key "${k.name}"? Scrapers using it will stop working immediately.`)) return;
    try {
      const nk = await api.revokeApiKey(k.id);
      keys.setData((xs) => xs.map((x) => (x.id === k.id ? nk : x)));
    } catch (x) {
      toast(x.message, 'error');
    }
  };

  return (
    <>
      <Card title="Create API key">
        <p className="muted small">Ingest scrapers and integrations authenticate with an API key in the <code>X-API-Key</code> header. Give each tool its own key with the fewest scopes it needs.</p>
        <form className="form-inline" onSubmit={create}>
          <label className="field grow"><span>Name</span>
            <input className="input" required maxLength={120} placeholder="pastebin-scraper" value={name} onChange={(e) => setName(e.target.value)} /></label>
          <div className="field"><span>Scopes</span>
            <div className="chips">
              {SCOPES.map((s) => (
                <button type="button" key={s} className={`chip ${scopes.includes(s) ? 'on' : ''}`}
                  onClick={() => setScopes(scopes.includes(s) ? scopes.filter((x) => x !== s) : [...scopes, s])}>{s}</button>
              ))}
            </div>
          </div>
          <div className="field"><span>&nbsp;</span><button className="btn btn-primary" disabled={!name.trim() || !scopes.length}><KeyRound size={14} /> Create</button></div>
        </form>
        <ErrorBox error={err} />
      </Card>
      <Card title="Keys">
        <ErrorBox error={keys.error} onRetry={keys.reload} />
        {keys.loading && !keys.data && <Spinner />}
        {keys.data?.length === 0 && <Empty title="No API keys" />}
        {keys.data?.length > 0 && (
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Name</th><th>Prefix</th><th>Scopes</th><th>Created</th><th>Last used</th><th>Status</th><th /></tr></thead>
              <tbody>
                {keys.data.map((k) => (
                  <tr key={k.id} className={k.revoked_at ? 'dim' : ''}>
                    <td>{k.name}</td>
                    <td className="mono">{k.prefix}…</td>
                    <td><div className="tags">{k.scopes?.map((s) => <Pill key={s}>{s}</Pill>)}</div></td>
                    <td className="nowrap">{fmtDate(k.created_at)}</td>
                    <td className="nowrap">{k.last_used_at ? relTime(k.last_used_at) : 'never'}</td>
                    <td>{k.revoked_at ? <Pill tone="critical">revoked</Pill> : <Pill tone="ok">active</Pill>}</td>
                    <td>{!k.revoked_at && <button className="btn btn-sm btn-danger" onClick={() => revoke(k)}>Revoke</button>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      {created && <NewKeyModal k={created} onClose={() => setCreated(null)} />}
    </>
  );
}

function NewKeyModal({ k, onClose }) {
  const curl = `curl -X POST '${window.location.origin}/leaks/ingest/webhook' \\
  -H 'X-API-Key: ${k.key}' \\
  -H 'Content-Type: application/json' \\
  -d '{"source": "${k.name.replace(/[^A-Za-z0-9_.-]/g, '-').slice(0, 64) || 'scraper'}", "title": "Paste mentioning acme", "source_url": "https://paste.example/abc", "content": "raw text that was found"}'`;
  return (
    <Modal title="API key created" onClose={onClose} wide footer={<button className="btn btn-primary" onClick={onClose}>I have stored the key</button>}>
      <div className="warn-box">
        <KeyRound size={16} />
        <div>This is the only time the full key is shown. Store it in your scraper's secret store now; it cannot be retrieved later.</div>
      </div>
      <label className="field">
        <span>Key <CopyButton text={k.key} /></span>
        <code className="mono-wrap secret">{k.key}</code>
      </label>
      <div className="muted small">Scopes: {k.scopes?.join(', ')}</div>
      {k.scopes?.includes('ingest') ? (
        <label className="field">
          <span>Example: push one finding <CopyButton text={curl} label="Copy curl" /></span>
          <pre className="json">{curl}</pre>
        </label>
      ) : <p className="muted small">This key lacks the <code>ingest</code> scope, so it cannot call the webhook.</p>}
    </Modal>
  );
}

function Tenants() {
  const tenants = useAsync(() => api.tenants(), []);
  const toast = useToast();
  const [form, setForm] = useState({ name: '', admin_email: '', admin_password: '' });
  const [err, setErr] = useState(null);
  const [deleting, setDeleting] = useState(null);

  const create = async (e) => {
    e.preventDefault();
    setErr(null);
    try {
      await api.createTenant(form);
      setForm({ name: '', admin_email: '', admin_password: '' });
      toast('Tenant created', 'ok');
      tenants.reload();
    } catch (x) {
      setErr(x);
    }
  };

  return (
    <>
      <Card title="Create tenant">
        <form className="form-inline" onSubmit={create}>
          <label className="field grow"><span>Organisation name</span>
            <input className="input" required minLength={2} maxLength={120} value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></label>
          <label className="field grow"><span>Admin email</span>
            <input className="input" type="email" required value={form.admin_email} onChange={(e) => setForm({ ...form, admin_email: e.target.value })} /></label>
          <label className="field grow"><span>Admin password (12+)</span>
            <input className="input" type="password" autoComplete="new-password" required minLength={12} value={form.admin_password}
              onChange={(e) => setForm({ ...form, admin_password: e.target.value })} /></label>
          <div className="field"><span>&nbsp;</span><button className="btn btn-primary"><Plus size={14} /> Create</button></div>
        </form>
        <ErrorBox error={err} />
      </Card>
      <Card title="Tenants">
        <ErrorBox error={tenants.error} onRetry={tenants.reload} />
        {tenants.loading && !tenants.data && <Spinner />}
        {tenants.data?.length > 0 && (
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Name</th><th>ID</th><th>Created</th><th /></tr></thead>
              <tbody>
                {tenants.data.map((t) => (
                  <tr key={t.id}>
                    <td>{t.name} {t.is_current && <Pill tone="vip">current</Pill>}</td>
                    <td className="mono">{t.id}</td>
                    <td className="nowrap">{fmtDate(t.created_at)}</td>
                    <td>{!t.is_current && (
                      <button className="icon-btn danger" onClick={() => setDeleting(t)} aria-label="Delete tenant"><Trash2 size={15} /></button>
                    )}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      {deleting && (
        <TypedConfirm
          title="Delete tenant"
          phrase={deleting.name}
          message={`This permanently deletes "${deleting.name}" with all of its users, watchlist, leaks, evidence and audit history.`}
          confirmLabel="Delete tenant"
          onClose={() => setDeleting(null)}
          onConfirm={async () => {
            const r = await api.deleteTenant(deleting.id);
            toast(r?.status === 'deleted' ? 'Tenant deleted' : 'Tenant deletion queued', 'ok');
            tenants.reload();
          }}
        />
      )}
    </>
  );
}

const LICENCE_STATE = {
  off: ['default', 'Licensing is not enabled on this build'],
  valid: ['ok', 'Active'],
  expired: ['critical', 'Expired: scanning is paused, data stays readable'],
  invalid: ['critical', 'Invalid licence'],
  missing: ['warn', 'No licence installed'],
};

function Licence() {
  const lic = useAsync(() => api.license(), []);
  const l = lic.data;
  const [tone, label] = l ? LICENCE_STATE[l.state] || ['default', l.state] : [];
  return (
    <Card title="Licence">
      <ErrorBox error={lic.error} onRetry={lic.reload} />
      {lic.loading && !l && <Spinner />}
      {l && (
        <div className="stack">
          <div><Pill tone={tone}>{label}</Pill>{l.reason && l.state !== 'valid' && <span className="small muted"> {l.reason}</span>}</div>
          {(l.state === 'valid' || l.state === 'expired') && (
            <dl className="kv">
              <dt>Customer</dt><dd>{l.customer}</dd>
              <dt>Expires</dt><dd>{l.expires}</dd>
              <dt>Domains</dt><dd>{l.domains_used} of {l.max_domains ?? 'unlimited'}</dd>
              {l.features?.length > 0 && <><dt>Features</dt><dd>{l.features.join(', ')}</dd></>}
            </dl>
          )}
          {l.state !== 'off' && <p className="fineprint">To renew, set LICENSE_KEY in .env and run <code>docker compose up -d</code>.</p>}
        </div>
      )}
    </Card>
  );
}
