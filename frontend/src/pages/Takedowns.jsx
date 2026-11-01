import React, { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Gavel, Mail, Plus, RefreshCw, Search, Send } from 'lucide-react';
import { api } from '../api';
import { Card, CopyButton, Drawer, Empty, ErrorBox, JsonView, KV, Modal, Pill, Spinner, StatusPill, fmtDate, relTime, useAsync, useToast } from '../components/ui';
import { Tile } from './Surface';

const FILTERS = [
  { key: 'open', label: 'Open' },
  { key: '', label: 'All' },
  { key: 'taken_down', label: 'Taken down' },
  { key: 'rejected', label: 'Rejected' },
];
const NEXT = {
  draft: [['submitted', 'Mark as sent', Send]],
  submitted: [['acknowledged', 'Acknowledged'], ['taken_down', 'Taken down'], ['rejected', 'Rejected']],
  acknowledged: [['taken_down', 'Taken down'], ['rejected', 'Rejected']],
  rejected: [['submitted', 'Re-submit']],
  taken_down: [['submitted', 'Reopen (back online)']],
  withdrawn: [['draft', 'Reopen']],
};
const REASONS = ['phishing', 'impersonation', 'trademark', 'data_leak', 'malware', 'fraud'];

export default function Takedowns() {
  const [params, setParams] = useSearchParams();
  const filter = FILTERS.some((f) => f.key === (params.get('status') ?? 'open')) ? (params.get('status') ?? 'open') : 'open';
  const list = useAsync(() => api.takedowns(filter ? { status: filter } : {}), [filter]);
  const stats = useAsync(() => api.takedownStats(), []);
  const [creating, setCreating] = useState(false);
  const openId = params.get('open');
  const s = stats.data;
  const reload = () => { list.reload(); stats.reload(); };
  const setOpen = (id) => {
    const p = new URLSearchParams(params);
    if (id) p.set('open', id); else p.delete('open');
    setParams(p);
  };

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Takedowns</h1>
          <p className="muted">Get phishing sites, lookalike domains, impersonating accounts and leaked data removed. Abuse contacts for the registrar and the hosting network are looked up over RDAP, the evidence is attached and a notice is drafted. You send it and record what happens.</p>
        </div>
        <button className="btn btn-primary" onClick={() => setCreating(true)}><Plus size={14} /> New request</button>
      </div>

      <div className="kpi-grid five">
        <Tile label="Open requests" value={s?.open} sub={s ? `${s.by_status.draft} draft · ${s.by_status.submitted} sent` : ''} tone={s?.by_status?.draft ? 'warn' : ''} />
        <Tile label="Taken down" value={s?.by_status?.taken_down} sub="confirmed offline" />
        <Tile label="Success rate" value={s?.success_rate != null ? `${s.success_rate}%` : undefined} sub="of closed requests" />
        <Tile label="Median time to takedown" value={s?.median_hours != null ? `${s.median_hours} h` : undefined} sub="from sending" />
        <Tile label="Rejected" value={s?.by_status?.rejected} sub="escalate or re-submit" tone={s?.by_status?.rejected ? 'warn' : ''} />
      </div>

      <div className="topo-toolbar">
        <div className="seg" role="group" aria-label="Status">
          {FILTERS.map((f) => <button key={f.key || 'all'} className={f.key === filter ? 'on' : ''} onClick={() => setParams(f.key === 'open' ? {} : { status: f.key })}>{f.label}</button>)}
        </div>
      </div>

      <ErrorBox error={list.error} onRetry={list.reload} />
      {list.loading && !list.data && <Spinner />}
      {list.data && list.data.length === 0 && (
        <div className="card"><Empty title="No takedown request here">Start one from a lookalike domain or phishing URL on Brand Protection, an impersonation on Executive Protection, or with <b>New request</b>.</Empty></div>
      )}
      {list.data?.length > 0 && (
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Request</th><th>Target</th><th>Reason</th><th>Status</th><th>Ask</th><th>Opened</th></tr></thead>
            <tbody>
              {list.data.map((t) => (
                <tr key={t.id} className="clickable" onClick={() => setOpen(t.id)}>
                  <td className="mono nowrap">{t.ref}</td>
                  <td>
                    <div className="asset-name mono ellipsis" title={t.target}>{t.target}</div>
                    <div className="sub">{t.kind}{t.source_type && t.source_type !== 'manual' ? ` · from ${t.source_type}` : ''}</div>
                  </td>
                  <td><Pill>{t.reason.replace('_', ' ')}</Pill></td>
                  <td><StatusPill status={t.status} /></td>
                  <td className="small">{t.contacts.length ? `${t.contacts[0].email}${t.contacts.length > 1 ? ` +${t.contacts.length - 1}` : ''}` : <span className="faint">no contact found</span>}</td>
                  <td className="nowrap muted">{relTime(t.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {openId && <TakedownDrawer id={openId} onClose={() => setOpen(null)} onChanged={reload} />}
      {creating && <NewTakedown onClose={() => setCreating(false)} onCreated={(td) => { setCreating(false); reload(); setOpen(td.id); }} />}
    </div>
  );
}

function TakedownDrawer({ id, onClose, onChanged }) {
  const d = useAsync(() => api.takedown(id), [id]);
  const [notice, setNotice] = useState('');
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);
  const [contact, setContact] = useState('');
  const toast = useToast();
  const t = d.data;
  useEffect(() => { if (t) setNotice(t.notice); }, [t?.id, t?.notice]);

  const run = async (fn, msg) => {
    setBusy(true);
    try {
      d.setData(await fn());
      if (msg) toast(msg, 'ok');
      setNote('');
      onChanged();
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      setBusy(false);
    }
  };
  const move = (status) => run(() => api.updateTakedown(id, { status, note, ...(notice !== t.notice ? { notice } : {}) }), `Marked ${status.replace('_', ' ')}`);
  const addContact = (e) => {
    e.preventDefault();
    if (!contact.trim()) return;
    run(() => api.updateTakedown(id, { contacts: [...t.contacts, { role: 'manual', email: contact.trim(), source: 'manual' }] }), 'Contact added');
    setContact('');
  };
  const subject = (t?.notice || '').split('\n')[0].replace(/^Subject:\s*/, '');
  const body = notice.split('\n').slice(2).join('\n');
  const mailto = t && t.contacts.length
    ? `mailto:${t.contacts.map((c) => c.email).join(',')}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}` : null;

  return (
    <Drawer title={t ? `${t.ref} · ${t.target}` : 'Takedown'} onClose={onClose}>
      <ErrorBox error={d.error} onRetry={d.reload} />
      {d.loading && !t && <Spinner />}
      {t && (
        <>
          <div className="id-head">
            <StatusPill status={t.status} />
            <div className="tags"><Pill>{t.kind}</Pill><Pill>{t.reason.replace('_', ' ')}</Pill>{t.age_days > 0 && <Pill>{t.age_days}d old</Pill>}</div>
          </div>

          <Card title="Workflow">
            <textarea className="input" rows={2} placeholder="Note for the history (ticket number, reply received…)" value={note} onChange={(e) => setNote(e.target.value)} />
            <div className="btn-row mt">
              {(NEXT[t.status] || []).map(([s, label, Icon]) => (
                <button key={s} className={`btn btn-sm ${s === 'taken_down' || s === 'submitted' ? 'btn-primary' : ''}`} disabled={busy} onClick={() => move(s)}>
                  {Icon && <Icon size={13} />} {label}
                </button>
              ))}
              {['draft', 'submitted', 'acknowledged'].includes(t.status) && <button className="btn btn-sm btn-ghost" disabled={busy} onClick={() => move('withdrawn')}>Withdraw</button>}
            </div>
          </Card>

          <Card title="Who to ask" actions={<button className="btn btn-sm btn-ghost" disabled={busy} onClick={() => run(() => api.relookupTakedown(id), 'RDAP looked up again')}><RefreshCw size={13} /> Re-lookup</button>}>
            <KV rows={[['Registrar', t.registrar || '—'], ['Hosting network', t.hosting || '—'],
              t.evidence?.resolved_ips?.length > 0 && ['Resolves to', <span className="mono">{t.evidence.resolved_ips.join(', ')}</span>]]} />
            {t.contacts.map((c) => (
              <div key={c.email} className="list-row">
                <Mail size={15} />
                <div className="list-main"><div className="list-title mono">{c.email}</div><div className="list-sub">{c.role}{c.name ? ` · ${c.name}` : ''} · {c.source}</div></div>
              </div>
            ))}
            {t.contacts.length === 0 && <p className="muted small">No abuse contact was found{t.evidence?.lookup_errors ? ` (${t.evidence.lookup_errors.join('; ')})` : ''}. Add one by hand, or use the registrar's abuse form.</p>}
            <form className="form-inline mt" onSubmit={addContact}>
              <input className="input" type="email" placeholder="abuse@registrar.example" value={contact} onChange={(e) => setContact(e.target.value)} />
              <button className="btn btn-sm" disabled={busy}><Plus size={13} /> Add contact</button>
            </form>
          </Card>

          <Card title="Notice" actions={<><CopyButton text={notice} />{mailto && <a className="btn btn-sm btn-primary" href={mailto}><Send size={13} /> Open in mail</a>}</>}>
            <textarea className="input mono notice-edit" rows={16} value={notice} onChange={(e) => setNotice(e.target.value)} />
            {notice !== t.notice && (
              <div className="btn-row mt"><button className="btn btn-sm" disabled={busy} onClick={() => run(() => api.updateTakedown(id, { notice }), 'Notice saved')}>Save notice</button></div>
            )}
          </Card>

          <Card title="History">
            {(t.history || []).slice().reverse().map((h, i) => (
              <div key={`${h.at}-${i}`} className="list-row">
                <StatusPill status={h.status} />
                <div className="list-main"><div className="list-title">{h.note || <span className="faint">status changed</span>}</div><div className="list-sub">{h.actor}</div></div>
                <span className="faint small nowrap">{fmtDate(h.at)}</span>
              </div>
            ))}
          </Card>
          <JsonView title="Evidence" data={t.evidence} />
        </>
      )}
    </Drawer>
  );
}

function NewTakedown({ onClose, onCreated }) {
  const [f, setF] = useState({ target: '', kind: 'url', reason: 'phishing' });
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);
  const go = async (e) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      onCreated(await api.createTakedown({ source_type: 'manual', ...f, target: f.target.trim() }));
    } catch (e2) {
      setErr(e2);
      setBusy(false);
    }
  };
  return (
    <Modal title="New takedown request" onClose={onClose} footer={
      <>
        <button className="btn" onClick={onClose}>Cancel</button>
        <button className="btn btn-primary" form="td-form" disabled={busy || !f.target.trim()}><Gavel size={14} /> {busy ? 'Looking up…' : 'Draft request'}</button>
      </>
    }>
      <form id="td-form" className="stack-form" onSubmit={go}>
        <label className="field"><span><Search size={13} /> Domain or URL to take down</span>
          <input className="input mono" autoFocus value={f.target} onChange={(e) => setF({ ...f, target: e.target.value })} placeholder="https://login-yourbrand.example/" />
        </label>
        <div className="grid-2">
          <label className="field"><span>Kind</span>
            <select className="input" value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value })}>
              {['url', 'domain', 'content', 'social'].map((k) => <option key={k} value={k}>{k}</option>)}
            </select>
          </label>
          <label className="field"><span>Reason</span>
            <select className="input" value={f.reason} onChange={(e) => setF({ ...f, reason: e.target.value })}>
              {REASONS.map((r) => <option key={r} value={r}>{r.replace('_', ' ')}</option>)}
            </select>
          </label>
        </div>
        <p className="fineprint">The registrar and hosting network are looked up over RDAP. Only request takedowns of content that abuses your organisation.</p>
        <ErrorBox error={err} />
      </form>
    </Modal>
  );
}
