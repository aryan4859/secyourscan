import React, { useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { Plus, Search, Trash2 } from 'lucide-react';
import { api } from '../api';
import { Card, Empty, ErrorBox, Pill, Spinner, Toggle, fmtDate, useAsync, useToast } from '../components/ui';

const TYPES = ['domain', 'email', 'keyword', 'ip', 'wallet'];
const PLACEHOLDER = {
  domain: 'acme.example.com',
  email: 'ceo@acme.example.com',
  keyword: 'project-falcon',
  ip: '203.0.113.10',
  wallet: 'bc1q…',
};

export default function Watchlist() {
  const list = useAsync(() => api.watchlist(), []);
  const toast = useToast();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const [type, setType] = useState('domain');
  const [value, setValue] = useState('');
  const [vip, setVip] = useState(false);
  const [busy, setBusy] = useState(false);
  const [formError, setFormError] = useState(null);
  const [filter, setFilter] = useState('');
  const inputRef = useRef(null);

  useEffect(() => {
    if (params.get('new')) {
      inputRef.current?.focus();
      setParams({}, { replace: true });
    }
  }, [params, setParams]);

  const add = async (e) => {
    e.preventDefault();
    setBusy(true);
    setFormError(null);
    try {
      const item = await api.addWatch({ type, value: value.trim(), is_vip: vip });
      list.setData((xs) => [...(xs || []), item]);
      setValue('');
      setVip(false);
      toast(`Watching ${item.type} ${item.value}`, 'ok');
    } catch (err) {
      setFormError(err);
    } finally {
      setBusy(false);
    }
  };

  const update = async (item, patch) => {
    try {
      const updated = await api.updateWatch(item.id, patch);
      list.setData((xs) => xs.map((x) => (x.id === item.id ? updated : x)));
    } catch (e) {
      toast(e.message, 'error');
    }
  };

  const remove = async (item) => {
    if (!window.confirm(`Stop watching ${item.type} "${item.value}"? Existing leaks are kept.`)) return;
    try {
      await api.deleteWatch(item.id);
      list.setData((xs) => xs.filter((x) => x.id !== item.id));
    } catch (e) {
      toast(e.message, 'error');
    }
  };

  const rows = useMemo(() => {
    const f = filter.trim().toLowerCase();
    return (list.data || []).filter((x) => !f || x.value.toLowerCase().includes(f) || x.type.includes(f));
  }, [list.data, filter]);

  const counts = useMemo(() => {
    const c = {};
    (list.data || []).forEach((x) => { c[x.type] = (c[x.type] || 0) + 1; });
    return c;
  }, [list.data]);

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Watchlist</h1>
          <p className="muted">Your organisation's own assets. Every ingested item is matched against the active entries; VIP entries raise severity.</p>
        </div>
      </div>

      <Card title="Add a watch item">
        <form className="form-inline" onSubmit={add}>
          <label className="field">
            <span>Type</span>
            <select className="input" value={type} onChange={(e) => setType(e.target.value)}>
              {TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
          </label>
          <label className="field grow">
            <span>Value</span>
            <input ref={inputRef} className="input" required minLength={3} maxLength={255} placeholder={PLACEHOLDER[type]}
              value={value} onChange={(e) => setValue(e.target.value)} />
          </label>
          <div className="field">
            <span>&nbsp;</span>
            <Toggle checked={vip} onChange={setVip} label="VIP" />
          </div>
          <div className="field">
            <span>&nbsp;</span>
            <button className="btn btn-primary" disabled={busy || value.trim().length < 3}><Plus size={14} /> Add</button>
          </div>
        </form>
        <ErrorBox error={formError} />
      </Card>

      <Card title={`Watched assets${list.data ? ` (${list.data.length})` : ''}`} actions={
        <div className="mini-search"><Search size={14} /><input className="input bare" placeholder="Filter…" value={filter} onChange={(e) => setFilter(e.target.value)} /></div>
      }>
        <div className="tags mb">
          {TYPES.map((t) => <Pill key={t}>{t}: {counts[t] || 0}</Pill>)}
        </div>
        <ErrorBox error={list.error} onRetry={list.reload} />
        {list.loading && !list.data && <Spinner />}
        {list.data && rows.length === 0 && (
          <Empty title={list.data.length ? 'No match for that filter' : 'Your watchlist is empty'}>
            {!list.data.length && 'Add your domains, executive mailboxes, project code names, public IPs and wallets.'}
          </Empty>
        )}
        {rows.length > 0 && (
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Type</th><th>Value</th><th>VIP</th><th>Active</th><th>Added</th><th /></tr></thead>
              <tbody>
                {rows.map((w) => (
                  <tr key={w.id} className={w.is_active ? '' : 'dim'}>
                    <td><Pill>{w.type}</Pill></td>
                    <td className="mono-wrap">
                      <button className="link" title="Show leaks mentioning this value"
                        onClick={() => navigate(`/leaks?q=${encodeURIComponent(w.value)}`)}>{w.value}</button>
                    </td>
                    <td><Toggle checked={w.is_vip} onChange={(v) => update(w, { is_vip: v })} /></td>
                    <td><Toggle checked={w.is_active} onChange={(v) => update(w, { is_active: v })} /></td>
                    <td className="nowrap">{fmtDate(w.created_at)}</td>
                    <td><button className="icon-btn danger" onClick={() => remove(w)} aria-label="Delete"><Trash2 size={15} /></button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
