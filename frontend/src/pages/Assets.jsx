import React, { useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  AtSign, Crown, ExternalLink, Globe, Hash, Plus, Search, Server, Wallet,
} from 'lucide-react';
import { api } from '../api';
import {
  Drawer, Empty, ErrorBox, Modal, Pill, SeverityBadge, Spinner, StatusPill, Toggle, fmtDate, relTime, useAsync, useToast,
} from '../components/ui';

const TYPES = ['domain', 'email', 'keyword', 'ip', 'wallet'];
const TYPE_ICON = { domain: Globe, email: AtSign, keyword: Hash, ip: Server, wallet: Wallet };
const PLACEHOLDER = { domain: 'acme.example.com', email: 'ceo@acme.example.com', keyword: 'project-falcon', ip: '203.0.113.10', wallet: 'bc1q…' };
const BANDS = ['critical', 'high', 'medium', 'low'];
const BAND_COLOR = { critical: 'var(--sev-critical)', high: 'var(--sev-high)', medium: 'var(--sev-medium)', low: 'var(--sev-low)' };
const bandOf = (v) => (v >= 80 ? 'critical' : v >= 60 ? 'high' : v >= 30 ? 'medium' : 'low');
const shortId = (id) => id.replace(/-/g, '').slice(0, 8).toUpperCase();

export default function Assets() {
  const rows = useAsync(() => api.watchExposure(), []);
  const [q, setQ] = useState('');
  const [type, setType] = useState('');
  const [vipOnly, setVipOnly] = useState(false);
  const [adding, setAdding] = useState(false);
  const [openId, setOpenId] = useState(null);
  const toast = useToast();

  const counts = useMemo(() => {
    const c = {};
    (rows.data || []).forEach((r) => { c[r.type] = (c[r.type] || 0) + 1; });
    return c;
  }, [rows.data]);

  const shown = useMemo(() => (rows.data || []).filter((r) => (!type || r.type === type) && (!vipOnly || r.is_vip)
    && (!q.trim() || r.value.toLowerCase().includes(q.trim().toLowerCase()))), [rows.data, type, vipOnly, q]);

  const exposed = (rows.data || []).filter((r) => r.exposure > 0).length;

  const setVip = async (r, v) => {
    try {
      await api.updateWatch(r.id, { is_vip: v });
      rows.setData((xs) => xs.map((x) => (x.id === r.id ? { ...x, is_vip: v } : x)));
      toast(`${r.value} ${v ? 'marked VIP' : 'no longer VIP'}`, 'ok');
    } catch (e) {
      toast(e.message, 'error');
    }
  };

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Asset Exposure</h1>
          <p className="muted">
            Every asset you watch, ranked by threat exposure: the severity of the worst leak still open against it.
            {rows.data && ` ${exposed} of ${rows.data.length} currently exposed.`}
          </p>
        </div>
        <button className="btn btn-primary" onClick={() => setAdding(true)}><Plus size={15} /> Add asset</button>
      </div>

      <div className="topo-toolbar">
        <div className="seg" role="group" aria-label="Asset type">
          <button className={!type ? 'on' : ''} onClick={() => setType('')}>All</button>
          {TYPES.filter((t) => counts[t]).map((t) => (
            <button key={t} className={type === t ? 'on' : ''} onClick={() => setType(t)}>{t} <span className="faint">{counts[t]}</span></button>
          ))}
        </div>
        <button className={`chip ${vipOnly ? 'on' : ''}`} onClick={() => setVipOnly((v) => !v)}><Crown size={12} /> VIP only</button>
        <label className="topo-search">
          <Search size={14} />
          <input className="input bare" placeholder="Filter assets…" value={q} onChange={(e) => setQ(e.target.value)} />
        </label>
      </div>

      <ErrorBox error={rows.error} onRetry={rows.reload} />
      {rows.loading && !rows.data && <Spinner />}
      {rows.data && rows.data.length === 0 && (
        <div className="card"><Empty title="No assets yet">Add the domains, mailboxes, keywords, IPs and wallets your organisation owns. Every leak is matched against them.</Empty></div>
      )}
      {rows.data && rows.data.length > 0 && (
        <div className="table-wrap asset-list">
          <table className="table">
            <thead>
              <tr><th>Asset identifier</th><th>Type</th><th className="w-expo">Threat exposure</th><th>Open</th><th>Hits</th><th>Last seen</th><th>VIP</th><th /></tr>
            </thead>
            <tbody>
              {shown.map((r) => {
                const Icon = TYPE_ICON[r.type] || Hash;
                return (
                  <tr key={r.id} className={`clickable ${r.is_active ? '' : 'dim'}`} onClick={() => setOpenId(r.id)}>
                    <td>
                      <div className="asset-id">
                        <span className={`asset-icon ${r.is_vip ? 'vip' : ''}`}>{r.is_vip ? <Crown size={14} /> : <Icon size={14} />}</span>
                        <span>
                          <div className="asset-name">{r.value}</div>
                          <div className="sub mono">{shortId(r.id)}{!r.is_active && ' · paused'}</div>
                        </span>
                      </div>
                    </td>
                    <td><Pill>{r.type}</Pill></td>
                    <td>
                      <div className="expo" title={r.exposure ? `Worst open leak: severity ${r.exposure}` : 'No open leaks'}>
                        <span className="expo-track"><span className="expo-fill" style={{ width: `${r.exposure}%`, background: BAND_COLOR[bandOf(r.exposure)] }} /></span>
                        <span className="expo-num">{r.exposure}</span>
                      </div>
                    </td>
                    <td className="mono">{r.open}{r.unacked_critical > 0 && <span className="error-text" title="Critical, unacknowledged"> · {r.unacked_critical}!</span>}</td>
                    <td className="mono">{r.hits}</td>
                    <td className="nowrap muted">{r.last_seen ? relTime(r.last_seen) : 'never'}</td>
                    <td onClick={(e) => e.stopPropagation()}><Toggle checked={r.is_vip} onChange={(v) => setVip(r, v)} /></td>
                    <td className="right"><button className="btn btn-sm" onClick={(e) => { e.stopPropagation(); setOpenId(r.id); }}>Insights</button></td>
                  </tr>
                );
              })}
              {shown.length === 0 && <tr><td colSpan={8}><Empty title="No asset matches these filters" /></td></tr>}
            </tbody>
          </table>
        </div>
      )}

      {adding && <AddAsset onClose={() => setAdding(false)} onAdded={() => { setAdding(false); rows.reload(); }} />}
      {openId && <AssetInsights id={openId} onClose={() => setOpenId(null)} onVip={(r, v) => setVip(r, v)} />}
    </div>
  );
}

function AddAsset({ onClose, onAdded }) {
  const [type, setType] = useState('domain');
  const [value, setValue] = useState('');
  const [vip, setVip] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  const toast = useToast();
  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      const item = await api.addWatch({ type, value: value.trim(), is_vip: vip });
      toast(`Watching ${item.type} ${item.value}`, 'ok');
      onAdded();
    } catch (e2) {
      setErr(e2);
      setBusy(false);
    }
  };
  return (
    <Modal title="Add asset" onClose={onClose} footer={
      <>
        <button className="btn" onClick={onClose}>Cancel</button>
        <button className="btn btn-primary" form="add-asset" disabled={busy || value.trim().length < 3}>{busy ? 'Adding…' : 'Add asset'}</button>
      </>
    }>
      <form id="add-asset" className="stack" onSubmit={submit}>
        <p className="muted small">Only assets your organisation owns. Leaks are matched against them from now on.</p>
        <label className="field">
          <span>Type</span>
          <select className="input" value={type} onChange={(e) => setType(e.target.value)}>
            {TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
        </label>
        <label className="field">
          <span>Value</span>
          <input className="input" autoFocus value={value} placeholder={PLACEHOLDER[type]} onChange={(e) => setValue(e.target.value)} />
        </label>
        <Toggle checked={vip} onChange={setVip} label="VIP: alert on every match, whatever the score" />
        <ErrorBox error={err} />
      </form>
    </Modal>
  );
}

function AssetInsights({ id, onClose, onVip }) {
  const ins = useAsync(() => api.watchInsights(id), [id]);
  const navigate = useNavigate();
  const d = ins.data;
  const totalBands = d ? BANDS.reduce((s, b) => s + d.bands[b], 0) : 0;
  return (
    <Drawer title={d ? d.value : 'Asset insights'} onClose={onClose} actions={d && (
      <Toggle checked={d.is_vip} onChange={(v) => { onVip(d, v); ins.setData((x) => ({ ...x, is_vip: v })); }} label="VIP" />
    )}>
      <ErrorBox error={ins.error} onRetry={ins.reload} />
      {ins.loading && !d && <Spinner />}
      {d && (
        <div className="stack">
          <div className="tags">
            <Pill>{d.type}</Pill>
            {d.is_vip && <Pill tone="vip">VIP</Pill>}
            {!d.is_active && <Pill tone="warn">paused</Pill>}
            <span className="faint small mono">{shortId(d.id)} · watched since {fmtDate(d.created_at)}</span>
          </div>

          <div className="mini-stats" style={{ gridTemplateColumns: 'repeat(4, minmax(0, 1fr))', marginTop: 4 }}>
            <div className="mini-stat"><div className="lbl">Threat exposure</div><div className="val" style={{ color: d.exposure ? BAND_COLOR[bandOf(d.exposure)] : undefined }}>{d.exposure}</div></div>
            <div className="mini-stat"><div className="lbl">Open leaks</div><div className="val">{d.open}</div></div>
            <div className="mini-stat"><div className="lbl">All hits</div><div className="val">{d.hits}</div></div>
            <div className="mini-stat"><div className="lbl">Unacked critical</div><div className="val">{d.unacked_critical}</div></div>
          </div>

          {d.hits === 0 ? (
            <Empty title="Not seen in any leak yet">Collected material is matched against this asset as it arrives.</Empty>
          ) : (
            <>
              <section className="detail-section">
                <h4>Severity of matching leaks</h4>
                <div className="funnel" role="img" aria-label="Matching leaks by severity">
                  {BANDS.filter((b) => d.bands[b]).map((b) => (
                    <span key={b} style={{ width: `${(d.bands[b] / totalBands) * 100}%`, background: BAND_COLOR[b] }} title={`${b}: ${d.bands[b]}`} />
                  ))}
                </div>
                <div className="legend">
                  {BANDS.map((b) => <span key={b}><span className="swatch" style={{ background: BAND_COLOR[b] }} /> {b} {d.bands[b]}</span>)}
                </div>
              </section>

              <section className="detail-section">
                <h4>Hits per day, last 90 days</h4>
                <DailyBars data={d.daily} />
                <div className="faint small">First seen {fmtDate(d.first_seen)} · last seen {relTime(d.last_seen)}</div>
              </section>

              <section className="detail-section grid-2">
                <div>
                  <h4>Sources</h4>
                  <div className="tags">{Object.entries(d.sources).map(([s, n]) => <Pill key={s}>{s} · {n}</Pill>)}</div>
                </div>
                <div>
                  <h4>Categories</h4>
                  <div className="tags">{Object.entries(d.categories).map(([c, n]) => <Pill key={c}>{c.toLowerCase()} · {n}</Pill>)}</div>
                </div>
              </section>

              <section className="detail-section">
                <h4>Most severe leaks</h4>
                {d.leaks.map((l) => (
                  <div key={l.id} className="stream-row" onClick={() => navigate(`/leaks?id=${encodeURIComponent(l.id)}`)}>
                    <SeverityBadge value={l.severity} />
                    <div className="list-main">
                      <div className="list-title">{l.title || l.id}</div>
                      <div className="list-sub">{l.source} · {relTime(l.discovered_at)}</div>
                    </div>
                    <StatusPill status={l.status} />
                  </div>
                ))}
              </section>
            </>
          )}
          <div className="btn-row">
            <button className="btn btn-sm" onClick={() => navigate(`/leaks?q=${encodeURIComponent(d.value)}`)}><ExternalLink size={13} /> Search all leaks for this asset</button>
          </div>
        </div>
      )}
    </Drawer>
  );
}

function DailyBars({ data }) {
  const [hover, setHover] = useState(null);
  const max = Math.max(...data.map((x) => x.count), 1);
  const W = 600;
  const H = 80;
  const step = W / data.length;
  return (
    <div className="chart">
      <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" style={{ height: H }} role="img"
        aria-label={`Hits per day, peak ${max}`} onMouseLeave={() => setHover(null)}>
        <line x1="0" x2={W} y1={H - 0.5} y2={H - 0.5} stroke="var(--grid)" />
        {data.map((x, i) => {
          const h = x.count ? Math.max((x.count / max) * (H - 4), 2) : 0;
          return (
            <g key={x.day} onMouseEnter={() => setHover(i)}>
              <rect x={i * step} y={0} width={step} height={H} fill={hover === i ? 'rgba(255,255,255,.05)' : 'transparent'} />
              {h > 0 && <rect x={i * step + 1} y={H - h} width={Math.max(step - 2, 1)} height={h} rx="1.5" fill="var(--series-1)" />}
            </g>
          );
        })}
      </svg>
      <div className="timeline-axis"><span>{data[0].day}</span><span>{hover != null ? `${data[hover].day}: ${data[hover].count}` : `peak ${max}/day`}</span><span>today</span></div>
    </div>
  );
}
