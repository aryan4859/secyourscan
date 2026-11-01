import React, { useEffect, useState } from 'react';
import { Flame, Layers, Plus, RefreshCw, Search, ShieldAlert, Skull, Trash2 } from 'lucide-react';
import { api } from '../api';
import { Card, Drawer, Empty, ErrorBox, KV, Pill, Spinner, relTime, useAsync, useToast } from '../components/ui';
import useDebounced from '../useDebounced';
import { Tile } from './Surface';

const PRIO_TONE = { critical: 'critical', high: 'warn', medium: 'default', low: 'default' };
const DAYS = [7, 30, 90];

export default function VulnIntel() {
  const [days, setDays] = useState(30);
  const [affecting, setAffecting] = useState(false);
  const [q, setQ] = useState('');
  const dq = useDebounced(q, 250);
  const feed = useAsync(() => api.vulnFeed({ days, affecting, q: dq || undefined }), [days, affecting, dq]);
  const [open, setOpen] = useState(null);
  const [stackOpen, setStackOpen] = useState(false);
  const toast = useToast();
  const d = feed.data;
  const running = ['queued', 'running'].includes(d?.refresh?.status);

  // Poll while a refresh runs.
  useEffect(() => {
    if (!running) return undefined;
    const t = setInterval(feed.reload, 3000);
    return () => clearInterval(t);
  }, [running, feed.reload]);

  const refresh = async () => {
    try {
      await api.vulnRefresh();
      toast('Refreshing CISA KEV, NVD and EPSS…');
      feed.reload();
    } catch (e) {
      toast(e.message, 'error');
    }
  };

  const st = d?.stats;
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Vulnerability Intelligence</h1>
          <p className="muted">New and actively exploited vulnerabilities, matched against your technology stack: what you declare plus what the attack-surface scan fingerprinted on your hosts. Prioritised by CISA KEV (exploited in the wild), FIRST EPSS (likely to be exploited) and CVSS.</p>
        </div>
        <div className="btn-row">
          <button className="btn" onClick={() => setStackOpen(true)}><Layers size={14} /> Tech stack{st ? ` (${st.stack})` : ''}</button>
          <button className="btn btn-primary" onClick={refresh} disabled={running}><RefreshCw size={14} className={running ? 'spin' : ''} /> {running ? 'Refreshing…' : 'Refresh feeds'}</button>
        </div>
      </div>

      <ErrorBox error={feed.error} onRetry={feed.reload} />
      {d?.refresh?.status === 'error' && <ErrorBox error={`Last refresh failed: ${d.refresh.error}`} />}

      <div className="kpi-grid five">
        <Tile label="Affecting your stack" value={st?.affecting} sub={`of ${st?.total ?? '—'} in the last ${days} days`} tone={st?.affecting ? 'crit' : ''} onClick={() => setAffecting(true)} />
        <Tile label="Exploited & affecting" value={st?.kev_affecting} sub="in CISA KEV" tone={st?.kev_affecting ? 'crit' : ''} onClick={() => setAffecting(true)} />
        <Tile label="Critical priority" value={st?.critical} sub={st ? `${st.high} high` : ''} tone={st?.critical ? 'crit' : st?.high ? 'warn' : ''} />
        <Tile label="Newly exploited" value={st?.kev} sub="added to KEV in window" />
        <Tile label="Used by ransomware" value={st?.ransomware} sub="KEV ransomware flag" tone={st?.ransomware ? 'warn' : ''} />
      </div>

      <div className="topo-toolbar">
        <div className="seg" role="group" aria-label="Window">
          {DAYS.map((x) => <button key={x} className={x === days ? 'on' : ''} onClick={() => setDays(x)}>{x}d</button>)}
        </div>
        <div className="seg" role="group" aria-label="Scope">
          <button className={!affecting ? 'on' : ''} onClick={() => setAffecting(false)}>All</button>
          <button className={affecting ? 'on' : ''} onClick={() => setAffecting(true)}>Affecting me</button>
        </div>
        <label className="topo-search"><Search size={14} />
          <input className="input bare" placeholder="CVE, vendor or product…" value={q} onChange={(e) => setQ(e.target.value)} />
        </label>
      </div>

      {feed.loading && !d && <Spinner />}
      {d && d.feeds.kev_entries === 0 && d.feeds.nvd_entries === 0 && (
        <div className="card"><Empty title="No feed data yet">Press <b>Refresh feeds</b> to download CISA KEV, NVD and EPSS (they then refresh every 6 hours).</Empty></div>
      )}
      {d?.items.length > 0 && (
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>CVE</th><th>Priority</th><th>Product</th><th>Signals</th><th>Affects you</th><th>Date</th></tr></thead>
            <tbody>
              {d.items.map((r) => (
                <tr key={r.cve} className="clickable" onClick={() => setOpen(r)}>
                  <td>
                    <div className="asset-name mono">{r.cve}</div>
                    <div className="sub ellipsis" title={r.title}>{r.title}</div>
                  </td>
                  <td><Pill tone={PRIO_TONE[r.priority]}>{r.priority}</Pill></td>
                  <td className="small">{[r.vendor, r.product].filter(Boolean).join(' ') || <span className="faint">—</span>}</td>
                  <td>
                    <div className="tags">
                      {r.kev && <Pill tone="critical" title={`Added ${r.kev_added}`}><Flame size={11} /> KEV</Pill>}
                      {r.ransomware && <Pill tone="critical"><Skull size={11} /> ransomware</Pill>}
                      {r.cvss != null && <Pill tone={r.cvss >= 9 ? 'critical' : r.cvss >= 7 ? 'warn' : 'default'}>CVSS {r.cvss}</Pill>}
                      {r.epss != null && <Pill tone={r.epss >= 0.1 ? 'warn' : 'default'} title={`percentile ${Math.round((r.percentile || 0) * 100)}`}>EPSS {(r.epss * 100).toFixed(1)}%</Pill>}
                    </div>
                  </td>
                  <td>
                    {r.affects.length ? (
                      <div className="tags">
                        {r.affects.slice(0, 2).map((a) => <Pill key={`${a.vendor}-${a.product}`} tone="critical">{a.product}{a.origin === 'detected' ? ' · seen' : ''}</Pill>)}
                        {r.hosts.length > 0 && <span className="faint small">{r.hosts.length} host(s)</span>}
                      </div>
                    ) : <span className="faint">—</span>}
                  </td>
                  <td className="nowrap muted">{r.date || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {d && d.items.length === 0 && (d.feeds.kev_entries > 0 || d.feeds.nvd_entries > 0) && (
        <div className="card"><Empty title={affecting ? 'Nothing in this window affects your stack' : 'No matching vulnerability'}>
          {affecting && st?.stack === 0 ? 'Your tech stack is empty: add the products you run.' : 'Try a longer window.'}
        </Empty></div>
      )}
      {d && (
        <div className="fineprint">
          KEV {d.feeds.kev_entries} entries · updated {relTime(d.feeds.kev_updated)} · NVD {d.feeds.nvd_entries} recent CVEs (CVSS ≥ 7) · updated {relTime(d.feeds.nvd_updated)} · EPSS {relTime(d.feeds.epss_updated)}.
          Matching is by vendor and product; version ranges are not evaluated.
        </div>
      )}

      {open && <CveDrawer r={open} onClose={() => setOpen(null)} />}
      {stackOpen && <StackDrawer onClose={() => { setStackOpen(false); feed.reload(); }} />}
    </div>
  );
}

function CveDrawer({ r, onClose }) {
  return (
    <Drawer title={r.cve} onClose={onClose} actions={
      <a className="btn btn-sm btn-ghost" href={`https://nvd.nist.gov/vuln/detail/${r.cve}`} target="_blank" rel="noreferrer noopener">NVD</a>
    }>
      <div className="tags mb">
        <Pill tone={PRIO_TONE[r.priority]}>{r.priority} priority</Pill>
        {r.kev && <Pill tone="critical"><Flame size={11} /> exploited in the wild</Pill>}
        {r.ransomware && <Pill tone="critical"><Skull size={11} /> used by ransomware</Pill>}
      </div>
      <Card title={r.title}>
        <p>{r.description || 'No description.'}</p>
        <KV rows={[
          ['Vendor / product', [r.vendor, r.product].filter(Boolean).join(' ') || '—'],
          ['CVSS v3', r.cvss != null ? `${r.cvss} (${r.severity || '—'})${r.vector ? ` · ${r.vector.toLowerCase()}` : ''}` : '—'],
          ['EPSS', r.epss != null ? `${(r.epss * 100).toFixed(2)}% · percentile ${Math.round((r.percentile || 0) * 100)}` : '—'],
          r.kev && ['In KEV since', r.kev_added],
          r.kev && r.kev_due && ['CISA due date', r.kev_due],
          r.action && ['Required action', r.action],
          ['Affected CPEs', r.products.length ? <span className="mono small">{r.products.slice(0, 8).join(', ')}</span> : '—'],
        ]} />
      </Card>
      <Card title="Your exposure">
        {r.affects.length === 0 ? <Empty title="Not matched to your stack" /> : r.affects.map((a) => (
          <div key={`${a.vendor}-${a.product}-${a.origin}`} className="list-row">
            <ShieldAlert size={16} className="crit" />
            <div className="list-main">
              <div className="list-title">{[a.vendor, a.product].filter(Boolean).join(' ')} {a.version && <span className="muted">· {a.version}</span>}</div>
              <div className="list-sub">{a.origin === 'detected' ? 'fingerprinted by the attack-surface scan' : 'declared in your tech stack'}{a.hosts.length > 0 && ` · ${a.hosts.join(', ')}`}</div>
            </div>
          </div>
        ))}
        <div className="fineprint">Version ranges are not checked: confirm the installed version is affected before patching.</div>
      </Card>
    </Drawer>
  );
}

function StackDrawer({ onClose }) {
  const stack = useAsync(() => api.techStack(), []);
  const [items, setItems] = useState(null);
  const [row, setRow] = useState({ vendor: '', product: '', version: '' });
  const [busy, setBusy] = useState(false);
  const toast = useToast();
  useEffect(() => { if (stack.data && items === null) setItems(stack.data.declared); }, [stack.data, items]);

  const add = (e) => {
    e.preventDefault();
    if (!row.product.trim()) return;
    setItems((xs) => [...xs, { ...row, critical: false }]);
    setRow({ vendor: '', product: '', version: '' });
  };
  const save = async () => {
    setBusy(true);
    try {
      await api.saveTechStack(items);
      toast('Tech stack saved', 'ok');
      onClose();
    } catch (e) {
      toast(e.message, 'error');
      setBusy(false);
    }
  };

  return (
    <Drawer title="Technology stack" onClose={onClose} actions={<button className="btn btn-primary btn-sm" disabled={busy || !items} onClick={save}>Save</button>}>
      <ErrorBox error={stack.error} onRetry={stack.reload} />
      {!items && <Spinner />}
      {items && (
        <>
          <Card title="Declared products">
            <form className="form-inline" onSubmit={add}>
              <input className="input" placeholder="Vendor (e.g. Fortinet)" value={row.vendor} onChange={(e) => setRow({ ...row, vendor: e.target.value })} />
              <input className="input" placeholder="Product (e.g. FortiOS)" value={row.product} onChange={(e) => setRow({ ...row, product: e.target.value })} required />
              <input className="input" placeholder="Version" value={row.version} onChange={(e) => setRow({ ...row, version: e.target.value })} style={{ maxWidth: 110 }} />
              <button className="btn"><Plus size={14} /> Add</button>
            </form>
            {items.length === 0 && <Empty title="Nothing declared">Add the edge devices, servers and SaaS you run: VPN, firewall, mail, CMS…</Empty>}
            {items.map((it, idx) => (
              <div key={`${it.vendor}-${it.product}-${idx}`} className="list-row">
                <Layers size={15} />
                <div className="list-main"><div className="list-title">{[it.vendor, it.product].filter(Boolean).join(' ')} {it.version && <span className="muted">· {it.version}</span>}</div></div>
                <button className="icon-btn" aria-label="Remove" onClick={() => setItems((xs) => xs.filter((_, i) => i !== idx))}><Trash2 size={14} /></button>
              </div>
            ))}
          </Card>
          <Card title="Detected on your hosts">
            {stack.data.detected.length === 0 ? <Empty title="Nothing fingerprinted yet">Run an attack-surface scan; CPEs from Shodan InternetDB appear here.</Empty> : stack.data.detected.map((dct) => (
              <div key={`${dct.vendor}-${dct.product}`} className="list-row">
                <Layers size={15} className="muted" />
                <div className="list-main">
                  <div className="list-title">{dct.vendor} {dct.product} {dct.versions.length > 0 && <span className="muted">· {dct.versions.join(', ')}</span>}</div>
                  <div className="list-sub">{dct.hosts.join(', ')}</div>
                </div>
              </div>
            ))}
          </Card>
          <div className="fineprint">Matching re-runs on every view, so changes apply as soon as you save.</div>
        </>
      )}
    </Drawer>
  );
}
