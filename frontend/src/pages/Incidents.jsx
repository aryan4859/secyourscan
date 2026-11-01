import React, { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { ArrowUpRight, Plus, RefreshCw, Send, Siren } from 'lucide-react';
import { api } from '../api';
import {
  Drawer, Empty, ErrorBox, KV, Modal, Pill, Spinner, fmtDate, relTime, statusLabel, useAsync, useToast,
} from '../components/ui';
import useDebounced from '../useDebounced';
import { Tile } from './Surface';

const STATUS_TABS = [
  ['active', 'Active'], ['open', 'Open'], ['investigating', 'Investigating'], ['contained', 'Contained'],
  ['closed', 'Closed'], ['all', 'All'],
];
const STATUSES = ['open', 'investigating', 'contained', 'resolved', 'false_positive'];
const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const SEV_TONE = { critical: 'critical', high: 'warn', medium: 'default', low: 'default' };
const SLA_TONE = { overdue: 'critical', at_risk: 'warn', on_track: 'default', met: 'ok', breached: 'critical' };
const SOURCE_PAGE = {
  leak: ['/leaks', 'Leaks'], vuln: ['/vulns', 'Vulnerabilities'], lookalike: ['/brand', 'Brand Protection'],
  phishing: ['/brand', 'Brand Protection'], ransomware: ['/ransomware', 'Ransomware'], surface: ['/surface', 'Attack Surface'],
  ioc: ['/iocs', 'IOC Hunting'], vendor: ['/supply-chain', 'Supply Chain'],
};

function parseIso(iso) {
  return new Date(iso && !iso.endsWith('Z') && !/[+-]\d\d:?\d\d$/.test(iso) ? `${iso}Z` : iso);
}

function duration(ms) {
  const m = Math.round(Math.abs(ms) / 60000);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h}h ${m % 60}m`;
  return `${Math.floor(h / 24)}d ${h % 24}h`;
}

export function SlaBadge({ inc }) {
  if (inc.sla_state === 'met') return <Pill tone="ok">SLA met</Pill>;
  if (inc.sla_state === 'breached') return <Pill tone="critical">SLA breached</Pill>;
  const left = parseIso(inc.sla_due_at) - Date.now();
  return (
    <Pill tone={SLA_TONE[inc.sla_state]} title={`Due ${fmtDate(inc.sla_due_at)}`}>
      {left < 0 ? `overdue ${duration(left)}` : `${duration(left)} left`}
    </Pill>
  );
}

export default function Incidents() {
  const [status, setStatus] = useState('active');
  const [severity, setSeverity] = useState('');
  const [assignee, setAssignee] = useState('');
  const [q, setQ] = useState('');
  const dq = useDebounced(q.trim(), 300);
  const list = useAsync(() => api.incidents({ status, severity, assignee, q: dq }), [status, severity, assignee, dq]);
  const stats = useAsync(() => api.incidentStats(), []);
  const people = useAsync(() => api.incidentAssignees(), []);
  const [openId, setOpenId] = useState(null);
  const [creating, setCreating] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const toast = useToast();

  const reload = useCallback(() => { list.reload(); stats.reload(); }, [list.reload, stats.reload]);

  const sync = async () => {
    setSyncing(true);
    try {
      const r = await api.syncIncidents();
      toast(r.opened ? `${r.opened} new incident(s) opened` : 'Nothing new: every finding already has an incident', 'ok');
      reload();
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      setSyncing(false);
    }
  };

  const s = stats.data;
  const rows = list.data || [];
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Incidents</h1>
          <p className="muted">One queue for every finding that needs a person: critical leaks, exploited CVEs, lookalike domains, phishing, ransomware posts, malicious IOCs on your assets and breached vendors. Each gets an owner, an SLA and a timeline.</p>
        </div>
        <div className="btn-row">
          <button className="btn" onClick={sync} disabled={syncing}><RefreshCw size={14} className={syncing ? 'spin' : ''} /> Sync findings</button>
          <button className="btn btn-primary" onClick={() => setCreating(true)}><Plus size={14} /> New incident</button>
        </div>
      </div>

      <div className="kpi-grid five">
        <Tile label="Active" value={s?.open} sub={s ? `${s.opened_7d} opened · ${s.closed_7d} closed in 7d` : ''} onClick={() => setStatus('active')} />
        <Tile label="Critical active" value={s?.by_severity_open.critical} sub={`SLA ${s?.sla_hours.critical ?? 4}h to resolve`}
          tone={s?.by_severity_open.critical ? 'crit' : ''} onClick={() => { setStatus('active'); setSeverity('critical'); }} />
        <Tile label="Overdue" value={s?.overdue} sub={s ? `${s.at_risk} at risk` : ''} tone={s?.overdue ? 'crit' : s?.at_risk ? 'warn' : ''} />
        <Tile label="Unassigned" value={s?.unassigned} sub="active, no owner" tone={s?.unassigned ? 'warn' : ''}
          onClick={() => { setStatus('active'); setAssignee('unassigned'); }} />
        <Tile label="MTTA · MTTR" value={s ? `${s.mtta_minutes ?? '—'}m · ${s.mttr_hours ?? '—'}h` : null}
          sub={s?.sla_met_pct != null ? `${s.sla_met_pct}% closed within SLA` : 'mean time to acknowledge · resolve'} />
      </div>

      <div className="tabs">
        {STATUS_TABS.map(([k, label]) => (
          <button key={k} className={k === status ? 'on' : ''} onClick={() => setStatus(k)}>
            {label}{k === 'active' && s ? ` · ${s.open}` : ''}
          </button>
        ))}
      </div>

      <div className="form-inline">
        <input className="input" style={{ maxWidth: 280 }} placeholder="Search title, description, actor…" value={q} onChange={(e) => setQ(e.target.value)} />
        <select className="input" value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="Severity">
          <option value="">Any severity</option>
          {SEVERITIES.map((x) => <option key={x} value={x}>{x}</option>)}
        </select>
        <select className="input" value={assignee} onChange={(e) => setAssignee(e.target.value)} aria-label="Assignee">
          <option value="">Anyone</option>
          <option value="me">Assigned to me</option>
          <option value="unassigned">Unassigned</option>
          {(people.data || []).map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
        </select>
      </div>

      <ErrorBox error={list.error} onRetry={list.reload} />
      {list.loading && !list.data && <Spinner />}
      {list.data && rows.length === 0 && (
        <div className="card"><Empty title={status === 'active' ? 'No active incidents' : 'No incidents match'}>
          Incidents open automatically after each scan. Use <b>Sync findings</b> to check now.
        </Empty></div>
      )}
      {rows.length > 0 && (
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Ref</th><th>Severity</th><th>Incident</th><th>Status</th><th>Owner</th><th>SLA</th><th>Opened</th></tr></thead>
            <tbody>
              {rows.map((i) => (
                <tr key={i.id} className="clickable" onClick={() => setOpenId(i.id)}>
                  <td className="mono nowrap">{i.ref}</td>
                  <td><Pill tone={SEV_TONE[i.severity]}>{i.severity}</Pill></td>
                  <td>
                    <div>{i.title}</div>
                    <div className="sub">{i.category}{i.actor && ` · ${i.actor}`}{i.tags.length > 0 && ` · ${i.tags.join(', ')}`}</div>
                  </td>
                  <td><span className={`pill st-${i.status}`}>{statusLabel(i.status)}</span></td>
                  <td className="nowrap">{i.assignee ? i.assignee.name : <span className="faint">unassigned</span>}</td>
                  <td><SlaBadge inc={i} /></td>
                  <td className="faint small nowrap" title={fmtDate(i.created_at)}>{relTime(i.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {openId && <IncidentDrawer id={openId} people={people.data || []} onClose={() => setOpenId(null)} onChanged={reload} />}
      {creating && <NewIncident people={people.data || []} onClose={() => setCreating(false)}
        onCreated={(inc) => { setCreating(false); reload(); setOpenId(inc.id); }} />}
    </div>
  );
}

function IncidentDrawer({ id, people, onClose, onChanged }) {
  const inc = useAsync(() => api.incident(id), [id]);
  const [comment, setComment] = useState('');
  const [busy, setBusy] = useState(false);
  const toast = useToast();
  const d = inc.data;

  const apply = async (fn) => {
    setBusy(true);
    try {
      inc.setData(await fn());
      onChanged();
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      setBusy(false);
    }
  };
  const update = (body) => apply(() => api.updateIncident(id, body));
  const send = async (e) => {
    e.preventDefault();
    if (!comment.trim()) return;
    await apply(() => api.commentIncident(id, comment.trim()));
    setComment('');
  };

  const src = d && SOURCE_PAGE[d.source_type];
  return (
    <Drawer title={d ? `${d.ref} · ${d.title}` : 'Incident'} onClose={onClose}>
      <ErrorBox error={inc.error} onRetry={inc.reload} />
      {!d && inc.loading && <Spinner />}
      {d && (
        <>
          <div className="form-inline">
            <label className="field"><span>Status</span>
              <select className="input" value={d.status} disabled={busy} onChange={(e) => update({ status: e.target.value })}>
                {STATUSES.map((x) => <option key={x} value={x}>{statusLabel(x)}</option>)}
              </select>
            </label>
            <label className="field"><span>Severity</span>
              <select className="input" value={d.severity} disabled={busy} onChange={(e) => update({ severity: e.target.value })}>
                {SEVERITIES.map((x) => <option key={x} value={x}>{x}</option>)}
              </select>
            </label>
            <label className="field"><span>Owner</span>
              <select className="input" value={d.assignee?.id || ''} disabled={busy}
                onChange={(e) => update({ assignee_id: e.target.value || null })}>
                <option value="">Unassigned</option>
                {people.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
              </select>
            </label>
          </div>

          <KV rows={[
            ['SLA', <span key="sla"><SlaBadge inc={d} /> <span className="faint small">due {fmtDate(d.sla_due_at)}</span></span>],
            ['Category', d.category],
            d.actor && ['Threat actor', <Link key="a" className="link" to="/actors">{d.actor} <ArrowUpRight size={11} /></Link>],
            ['Opened', `${fmtDate(d.created_at)} by ${d.created_by}`],
            d.acknowledged_at && ['Acknowledged', fmtDate(d.acknowledged_at)],
            d.resolved_at && ['Closed', fmtDate(d.resolved_at)],
            src && ['Finding', <Link key="s" className="link" to={src[0]}>{src[1]} <ArrowUpRight size={11} /></Link>],
          ]} />

          {d.description && <pre className="incident-desc">{d.description}</pre>}

          <h4 className="section-title">Timeline</h4>
          <ul className="timeline-list">
            {d.events.map((e) => (
              <li key={e.id} className={e.kind === 'created' ? 'tl-warning' : ''}>
                <span className="tl-dot" />
                <div className="tl-main">
                  <div className="tl-head"><b className="small">{e.actor}</b> <span className="faint small">{e.kind} · {relTime(e.at)}</span></div>
                  <div className="tl-detail">{e.body}</div>
                </div>
              </li>
            ))}
          </ul>

          <form className="input-group mt" onSubmit={send}>
            <input className="input" placeholder="Add a comment…" value={comment} maxLength={4000} onChange={(e) => setComment(e.target.value)} />
            <button className="btn" disabled={busy || !comment.trim()}><Send size={14} /> Comment</button>
          </form>
        </>
      )}
    </Drawer>
  );
}

function NewIncident({ people, onClose, onCreated }) {
  const [form, setForm] = useState({ title: '', description: '', severity: 'medium', assignee_id: '' });
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);
  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }));
  useEffect(() => setErr(null), [form]);

  const submit = async () => {
    setBusy(true);
    try {
      onCreated(await api.createIncident({ ...form, assignee_id: form.assignee_id || null }));
    } catch (e) {
      setErr(e);
      setBusy(false);
    }
  };
  return (
    <Modal title="New incident" onClose={onClose} footer={
      <>
        <button className="btn" onClick={onClose}>Cancel</button>
        <button className="btn btn-primary" disabled={busy || form.title.trim().length < 3} onClick={submit}><Siren size={14} /> Open incident</button>
      </>
    }>
      <div className="stack">
        <label className="field"><span>Title <span className="req">*</span></span>
          <input className="input" autoFocus value={form.title} maxLength={255} onChange={set('title')} placeholder="e.g. Suspicious OAuth consent in Microsoft 365" />
        </label>
        <label className="field"><span>Description</span>
          <textarea className="input" rows={5} value={form.description} maxLength={8000} onChange={set('description')} />
        </label>
        <div className="form-inline">
          <label className="field"><span>Severity</span>
            <select className="input" value={form.severity} onChange={set('severity')}>
              {SEVERITIES.map((x) => <option key={x} value={x}>{x}</option>)}
            </select>
          </label>
          <label className="field"><span>Owner</span>
            <select className="input" value={form.assignee_id} onChange={set('assignee_id')}>
              <option value="">Unassigned</option>
              {people.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
            </select>
          </label>
        </div>
        <ErrorBox error={err} />
      </div>
    </Modal>
  );
}
