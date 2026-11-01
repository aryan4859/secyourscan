import React, { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { ExternalLink, Plus, Skull, Trash2, TrendingDown, TrendingUp, Upload } from 'lucide-react';
import { api } from '../api';
import ScanBar from '../components/ScanBar';
import { Card, Drawer, Empty, ErrorBox, KV, Modal, Pill, Spinner, fmtDate, relTime, useAsync, useToast } from '../components/ui';
import { Tile } from './Surface';

const CRIT = ['critical', 'high', 'medium', 'low'];
const CRIT_TONE = { critical: 'critical', high: 'warn', medium: 'default', low: 'default' };
const AREA = { breach: 'Breach', reputation: 'Threat feeds', vulns: 'Vulnerabilities', network: 'Exposed services', tls: 'Web TLS', email: 'Email & DNS', leaks: 'Your leaks' };

function Grade({ grade }) {
  return grade ? <span className={`grade grade-${grade}`}>{grade}</span> : <span className="grade grade-none" title="Not scanned yet">–</span>;
}

export default function SupplyChain() {
  const list = useAsync(() => api.vendors(), []);
  const summary = useAsync(() => api.vendorSummary(), []);
  const [openId, setOpenId] = useState(null);
  const [importing, setImporting] = useState(false);
  const reload = useCallback(() => { list.reload(); summary.reload(); }, [list.reload, summary.reload]);
  const s = summary.data;
  const rows = list.data || [];

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Supply Chain Risk</h1>
          <p className="muted">An outside-in rating of each vendor from public data only: email and DNS security, website TLS, exposed services and known CVEs (Shodan InternetDB), threat-feed listings, and ransomware leak-site posts. A vendor named on a leak site opens an incident.</p>
        </div>
        <ScanBar module="vendors" label="Vendor" onFinished={reload} />
      </div>

      <div className="kpi-grid five">
        <Tile label="Vendors" value={s?.vendors} sub={s ? `${s.rated} rated` : ''} />
        <Tile label="Average score" value={s?.average ?? '—'} sub="0–100, higher is safer" />
        <Tile label="Breached" value={s?.breached} sub="named on a leak site" tone={s?.breached ? 'crit' : ''} />
        <Tile label="Key vendors at risk" value={s?.critical_at_risk} sub="critical/high, graded D or F" tone={s?.critical_at_risk ? 'crit' : ''} />
        <Tile label="Grades" value={s ? 'ABCDF'.split('').map((g) => s.by_grade[g]).join(' · ') : null} sub="A · B · C · D · F" />
      </div>

      <AddVendor onAdded={reload} onImport={() => setImporting(true)} />

      <ErrorBox error={list.error} onRetry={list.reload} />
      {list.loading && !list.data && <Spinner />}
      {list.data && rows.length === 0 && (
        <div className="card"><Empty title="No vendors yet">Add the third parties that hold your data or connect to your network, then run a scan.</Empty></div>
      )}
      {rows.length > 0 && (
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Grade</th><th>Vendor</th><th>Criticality</th><th>Score</th><th>Top issues</th><th>Scanned</th></tr></thead>
            <tbody>
              {rows.map((v) => (
                <tr key={v.id} className="clickable" onClick={() => setOpenId(v.id)}>
                  <td><Grade grade={v.grade} /></td>
                  <td>
                    <div>{v.name} {v.breaches > 0 && <Pill tone="critical"><Skull size={11} /> breached</Pill>}</div>
                    <div className="sub">{v.domain}{v.category && ` · ${v.category}`}</div>
                  </td>
                  <td><Pill tone={CRIT_TONE[v.criticality]}>{v.criticality}</Pill></td>
                  <td className="nowrap">
                    {v.score ?? <span className="faint">—</span>}
                    {v.trend > 0 && <span className="chain-ok small"> <TrendingUp size={12} />+{v.trend}</span>}
                    {v.trend < 0 && <span className="chain-bad small"> <TrendingDown size={12} />{v.trend}</span>}
                  </td>
                  <td className="small">{v.top_findings.length ? v.top_findings.join(' · ') : <span className="faint">{v.score != null ? 'none' : 'not scanned'}</span>}</td>
                  <td className="faint small nowrap">{relTime(v.last_scanned_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {openId && <VendorDrawer id={openId} onClose={() => setOpenId(null)} onChanged={reload} onDeleted={() => { setOpenId(null); reload(); }} />}
      {importing && <ImportVendors onClose={() => setImporting(false)} onDone={() => { setImporting(false); reload(); }} />}
    </div>
  );
}

function AddVendor({ onAdded, onImport }) {
  const [f, setF] = useState({ name: '', domain: '', criticality: 'medium' });
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);
  const toast = useToast();
  const set = (k) => (e) => setF((x) => ({ ...x, [k]: e.target.value }));
  const add = async (e) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      const v = await api.addVendor(f);
      toast(`${v.name} added: run a scan to rate it`, 'ok');
      setF({ name: '', domain: '', criticality: 'medium' });
      onAdded();
    } catch (e2) {
      setErr(e2);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Card title="Add a vendor" actions={<button className="btn btn-sm" onClick={onImport}><Upload size={13} /> Import CSV</button>}>
      <form className="form-inline" onSubmit={add}>
        <label className="field grow"><span>Name</span><input className="input" value={f.name} onChange={set('name')} placeholder="Acme Payroll" /></label>
        <label className="field grow"><span>Domain</span><input className="input" value={f.domain} onChange={set('domain')} placeholder="acmepayroll.com" /></label>
        <label className="field"><span>Criticality</span>
          <select className="input" value={f.criticality} onChange={set('criticality')}>{CRIT.map((c) => <option key={c} value={c}>{c}</option>)}</select>
        </label>
        <button className="btn btn-primary" disabled={busy || f.name.trim().length < 2 || f.domain.trim().length < 4}><Plus size={14} /> Add</button>
      </form>
      <ErrorBox error={err} />
    </Card>
  );
}

function Sparkline({ history }) {
  if (!history || history.length < 2) return null;
  const w = 240, h = 48, pad = 4;
  const pts = history.map((p, i) => [pad + (i * (w - 2 * pad)) / (history.length - 1), h - pad - (p.score / 100) * (h - 2 * pad)]);
  return (
    <svg className="sparkline" viewBox={`0 0 ${w} ${h}`} role="img" aria-label={`Score history: ${history.map((p) => p.score).join(', ')}`}>
      <polyline points={pts.map((p) => p.join(',')).join(' ')} fill="none" strokeWidth="2" />
      {pts.map(([x, y], i) => <circle key={i} cx={x} cy={y} r="2.5"><title>{`${fmtDate(history[i].at)}: ${history[i].score} (${history[i].grade})`}</title></circle>)}
    </svg>
  );
}

function VendorDrawer({ id, onClose, onChanged, onDeleted }) {
  const r = useAsync(() => api.vendor(id), [id]);
  const [notes, setNotes] = useState('');
  const toast = useToast();
  const d = r.data;
  useEffect(() => { if (d) setNotes(d.notes || ''); }, [d?.id]); // eslint-disable-line react-hooks/exhaustive-deps

  const update = async (body, msg) => {
    try {
      r.setData(await api.updateVendor(id, body));
      if (msg) toast(msg, 'ok');
      onChanged();
    } catch (e) {
      toast(e.message, 'error');
    }
  };
  const remove = async () => {
    try {
      await api.deleteVendor(id);
      onDeleted();
    } catch (e) {
      toast(e.message, 'error');
    }
  };
  const areas = {};
  (d?.findings || []).forEach((f) => { (areas[f.area] = areas[f.area] || []).push(f); });
  const facts = d?.facts || {};
  return (
    <Drawer title={d ? d.name : 'Vendor'} onClose={onClose}
      actions={d && <button className="icon-btn danger" onClick={remove} title="Remove vendor"><Trash2 size={16} /></button>}>
      <ErrorBox error={r.error} onRetry={r.reload} />
      {!d && r.loading && <Spinner />}
      {d && (
        <div className="stack">
          <div className="vendor-hero">
            <Grade grade={d.grade} />
            <div>
              <div className="vendor-score">{d.score ?? '—'}<span className="faint small"> / 100</span></div>
              <div className="faint small">{d.domain} · last scan {d.last_scanned_at ? fmtDate(d.last_scanned_at) : 'never'}</div>
            </div>
            <Sparkline history={d.history} />
          </div>

          {d.breach_posts.length > 0 && (
            <div className="rw-hit new">
              <div className="rw-icon"><Skull size={20} /></div>
              <div className="rw-main">
                <div className="rw-title">Named on a ransomware leak site</div>
                {d.breach_posts.map((b) => (
                  <div key={`${b.group}-${b.victim}`} className="list-sub">
                    <b>{b.group}</b> · “{b.victim}”{b.date && ` · ${fmtDate(b.date)}`}
                    {b.url && <a className="link ext" href={b.url} target="_blank" rel="noreferrer noopener"><ExternalLink size={11} /></a>}
                  </div>
                ))}
                <div className="small mt">Find out what data you share with them, rotate any shared credentials, and ask for their incident report. <Link className="link" to="/incidents">See incident</Link></div>
              </div>
            </div>
          )}

          <h4 className="section-title">Findings</h4>
          {d.score != null && d.findings.length === 0 && <div className="chain-ok small">No issues found in public data.</div>}
          {d.score == null && <div className="faint small">Not scanned yet. Use “Scan now” above.</div>}
          {Object.entries(areas).map(([area, fs]) => (
            <div key={area}>
              <div className="faint small tactic-label">{AREA[area] || area} · −{fs.reduce((n, f) => n + f.penalty, 0)}</div>
              {fs.map((f, i) => (
                <div key={i} className="list-row">
                  <Pill tone={f.severity === 'critical' ? 'critical' : f.severity === 'high' ? 'warn' : 'default'}>{f.severity}</Pill>
                  <div className="list-main"><div>{f.title}</div><div className="list-sub mono-wrap">{f.detail}</div></div>
                  <span className="faint small">−{f.penalty}</span>
                </div>
              ))}
            </div>
          ))}

          {d.last_scanned_at && (
            <KV rows={[
              ['Web IPs', (facts.ips || []).join(', ') || '—'],
              ['Open ports', (facts.ports || []).join(', ') || '—'],
              ['Known CVEs', (facts.cves || []).join(', ') || '—'],
              ['Website TLS', facts.tls_grade || 'no HTTPS answer'],
            ]} />
          )}

          <div className="form-inline">
            <label className="field"><span>Criticality</span>
              <select className="input" value={d.criticality} onChange={(e) => update({ criticality: e.target.value })}>
                {CRIT.map((c) => <option key={c} value={c}>{c}</option>)}
              </select>
            </label>
            <label className="field grow"><span>Category</span>
              <input className="input" defaultValue={d.category || ''} placeholder="SaaS, payroll, MSP…"
                onBlur={(e) => e.target.value !== (d.category || '') && update({ category: e.target.value || null })} />
            </label>
            <label className="field grow"><span>Security contact</span>
              <input className="input" defaultValue={d.contact || ''} placeholder="security@vendor.com"
                onBlur={(e) => e.target.value !== (d.contact || '') && update({ contact: e.target.value || null })} />
            </label>
          </div>
          <label className="field"><span>Notes</span>
            <textarea className="input" rows={3} value={notes} onChange={(e) => setNotes(e.target.value)}
              onBlur={() => notes !== (d.notes || '') && update({ notes }, 'Notes saved')} />
          </label>
        </div>
      )}
    </Drawer>
  );
}

function ImportVendors({ onClose, onDone }) {
  const [csv, setCsv] = useState('');
  const [res, setRes] = useState(null);
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);
  const submit = async () => {
    setBusy(true);
    setErr(null);
    try {
      setRes(await api.importVendors(csv));
    } catch (e) {
      setErr(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal title="Import vendors" onClose={res ? onDone : onClose} footer={res
      ? <button className="btn btn-primary" onClick={onDone}>Done</button>
      : <>
        <button className="btn" onClick={onClose}>Cancel</button>
        <button className="btn btn-primary" disabled={busy || !csv.trim()} onClick={submit}><Upload size={14} /> Import</button>
      </>}>
      {!res && (
        <div className="stack">
          <p className="faint small">One vendor per line: <code>name,domain[,criticality[,category]]</code>. A header row is skipped.</p>
          <textarea className="input code" rows={8} value={csv} onChange={(e) => setCsv(e.target.value)}
            placeholder={'name,domain,criticality,category\nAcme Payroll,acmepayroll.com,critical,payroll\nCloudCo,cloudco.io,high,SaaS'} />
          <ErrorBox error={err} />
        </div>
      )}
      {res && (
        <div className="stack">
          <div><b>{res.added}</b> vendor(s) added.</div>
          {res.skipped.length > 0 && <div className="faint small">Skipped (duplicate or invalid): {res.skipped.join('; ')}</div>}
        </div>
      )}
    </Modal>
  );
}
