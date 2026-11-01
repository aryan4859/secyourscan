import React, { useCallback, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Fish, Gavel, Globe, Lock, Mail, Search } from 'lucide-react';
import { api } from '../api';
import ScanBar from '../components/ScanBar';
import SourcesPanel from '../components/SourcesPanel';
import { CopyButton, Empty, ErrorBox, Pill, Spinner, relTime, useAsync, useToast } from '../components/ui';
import { Tile } from './Surface';

const STATUSES = [
  { key: 'new', label: 'New' },
  { key: 'reviewing', label: 'Reviewing' },
  { key: 'takedown', label: 'Takedown requested' },
  { key: 'benign', label: 'Benign' },
];
const riskColor = (r) => (r >= 85 ? 'var(--sev-critical)' : r >= 70 ? 'var(--sev-high)' : r >= 50 ? 'var(--sev-medium)' : 'var(--sev-low)');

export default function Brand() {
  const list = useAsync(() => api.lookalikes(), []);
  const phish = useAsync(() => api.phishing(), []);
  const status = useAsync(() => api.intelStatus(), []);
  const [q, setQ] = useState('');
  const [minRisk, setMinRisk] = useState(0);
  const [hideBenign, setHideBenign] = useState(true);
  const toast = useToast();
  const navigate = useNavigate();
  const reload = useCallback(() => { list.reload(); phish.reload(); status.reload(); }, [list.reload, phish.reload, status.reload]);
  const requestTakedown = async (sourceType, id) => {
    try {
      const td = await api.createTakedown({ source_type: sourceType, source_id: id, reason: 'phishing' });
      toast(`${td.ref} drafted: abuse contacts looked up`, 'ok');
      navigate(`/takedowns?open=${td.id}`);
    } catch (e) {
      if (e.status === 409) navigate('/takedowns');
      toast(e.message, 'error');
    }
  };
  const last = status.data?.brand?.result || {};
  const setPhishStatus = async (p, s) => {
    try {
      await api.updatePhishing(p.id, s);
      phish.setData((xs) => xs.map((y) => (y.id === p.id ? { ...y, status: s } : y)));
    } catch (e) {
      toast(e.message, 'error');
    }
  };
  const rows = list.data || [];

  const shown = useMemo(() => rows.filter((x) => x.risk >= minRisk && (!hideBenign || x.status !== 'benign')
    && (!q.trim() || x.domain.includes(q.trim().toLowerCase()))), [rows, minRisk, hideBenign, q]);

  const setStatus = async (x, status) => {
    try {
      await api.updateLookalike(x.id, status);
      list.setData((xs) => xs.map((y) => (y.id === x.id ? { ...y, status } : y)));
    } catch (e) {
      toast(e.message, 'error');
    }
  };

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Brand Protection</h1>
          <p className="muted">Registered domains that imitate yours: typos, homoglyphs, combosquats and TLD swaps. Risk rises with what phishing needs: a web server, mail (MX) and a certificate.</p>
        </div>
        <ScanBar module="brand" label="Lookalike" onFinished={reload} />
      </div>

      <div className="kpi-grid five">
        <Tile label="Registered lookalikes" value={rows.length} sub="of generated permutations" />
        <Tile label="High risk" value={rows.filter((x) => x.risk >= 70 && x.status !== 'benign').length} sub="risk ≥ 70" tone={rows.some((x) => x.risk >= 70 && x.status !== 'benign') ? 'crit' : ''} />
        <Tile label="Can send mail" value={rows.filter((x) => x.has_mx).length} sub="MX record present" tone={rows.some((x) => x.has_mx) ? 'warn' : ''} />
        <Tile label="Live phishing URLs" value={(phish.data || []).filter((p) => ['new', 'reported'].includes(p.status)).length} sub="OpenPhish · PhishStats" tone={(phish.data || []).some((p) => p.status === 'new') ? 'crit' : ''} />
        <Tile label="Takedowns" value={rows.filter((x) => x.status === 'takedown').length} sub="requested" />
      </div>

      {phish.data?.length > 0 && (
        <section className="card phish-card">
          <header className="card-head"><h2><Fish size={15} /> Phishing URLs using your brand</h2><span className="faint small">from public phishing feeds</span></header>
          <div className="card-body">
            <div className="table-wrap" style={{ border: 0 }}>
              <table className="table">
                <thead><tr><th>URL</th><th>Targets</th><th>Feed</th><th>First seen</th><th>Status</th></tr></thead>
                <tbody>
                  {phish.data.map((p) => (
                    <tr key={p.id} className={['down', 'benign'].includes(p.status) ? 'dim' : ''}>
                      <td><code className="phish-url">{p.url}</code>{p.ip && <div className="sub mono">{p.ip}</div>}</td>
                      <td className="mono small">{p.target}</td>
                      <td><Pill>{p.source}</Pill></td>
                      <td className="nowrap muted">{relTime(p.first_seen)}</td>
                      <td>
                        <div className="btn-row">
                          <select className="input input-sm" value={p.status} onChange={(e) => setPhishStatus(p, e.target.value)} aria-label={`Status of ${p.host}`}>
                            <option value="new">New</option><option value="reported">Reported</option><option value="down">Taken down</option><option value="benign">Not phishing</option>
                          </select>
                          <CopyButton text={p.url} label="" />
                          {['new', 'reported'].includes(p.status) && (
                            <button className="btn btn-sm" title="Draft a takedown request" onClick={() => requestTakedown('phishing', p.id)}><Gavel size={13} /></button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </section>
      )}

      <div className="topo-toolbar">
        <div className="seg" role="group" aria-label="Minimum risk">
          {[0, 50, 70, 85].map((r) => <button key={r} className={r === minRisk ? 'on' : ''} onClick={() => setMinRisk(r)}>{r ? `Risk ≥ ${r}` : 'Any risk'}</button>)}
        </div>
        <button className={`chip ${hideBenign ? 'on' : ''}`} onClick={() => setHideBenign((v) => !v)}>Hide benign</button>
        <label className="topo-search"><Search size={14} />
          <input className="input bare" placeholder="Filter domains…" value={q} onChange={(e) => setQ(e.target.value)} />
        </label>
      </div>

      <ErrorBox error={list.error} onRetry={list.reload} />
      {list.loading && !list.data && <Spinner />}
      {list.data && rows.length === 0 && (
        <div className="card"><Empty title="No registered lookalikes found">Scans check a few hundred permutations of every domain on your Watchlist.</Empty></div>
      )}
      {rows.length > 0 && (
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Lookalike domain</th><th>Imitates</th><th>Technique</th><th className="w-expo">Risk</th><th>Capabilities</th><th>First seen</th><th>Status</th></tr></thead>
            <tbody>
              {shown.map((x) => (
                <tr key={x.id} className={x.status === 'benign' ? 'dim' : ''}>
                  <td>
                    <div className="asset-name mono">{x.domain} {x.is_new && <Pill tone="warn">new</Pill>}</div>
                    <div className="sub mono">{x.ips.join(', ') || 'no A record'}</div>
                  </td>
                  <td className="mono small">{x.target}</td>
                  <td><Pill>{x.technique}</Pill></td>
                  <td>
                    <div className="expo">
                      <span className="expo-track"><span className="expo-fill" style={{ width: `${x.risk}%`, background: riskColor(x.risk) }} /></span>
                      <span className="expo-num">{x.risk}</span>
                    </div>
                  </td>
                  <td>
                    <div className="caps">
                      <span className={x.ips.length ? 'on' : ''} title="Web server (A record)"><Globe size={13} /></span>
                      <span className={x.has_mx ? 'on' : ''} title="Mail (MX record)"><Mail size={13} /></span>
                      <span className={x.has_cert ? 'on' : ''} title="TLS certificate issued"><Lock size={13} /></span>
                    </div>
                  </td>
                  <td className="nowrap muted">{relTime(x.first_seen)}</td>
                  <td>
                    <div className="btn-row">
                      <select className="input input-sm" value={x.status} onChange={(e) => setStatus(x, e.target.value)} aria-label={`Status of ${x.domain}`}>
                        {STATUSES.map((s) => <option key={s.key} value={s.key}>{s.label}</option>)}
                      </select>
                      <CopyButton text={x.domain} label="" />
                      {x.status !== 'benign' && (
                        <button className="btn btn-sm" title="Draft a takedown request" onClick={() => requestTakedown('lookalike', x.id)}><Gavel size={13} /></button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
              {shown.length === 0 && <tr><td colSpan={7}><Empty title="No lookalike matches these filters" /></td></tr>}
            </tbody>
          </table>
        </div>
      )}
      <SourcesPanel sources={[
        { key: 'registered', label: 'DNS (A and MX records)', desc: `${last.checked ?? '…'} permutations of your domains checked; only registered ones are kept` },
        { key: 'openphish', label: 'OpenPhish community feed', href: 'https://openphish.com', desc: 'Phishing URLs confirmed in the last hours' },
        { key: 'phishstats', label: 'PhishStats', href: 'https://phishstats.info', desc: 'Searchable phishing URL database, queried for your brand name' },
        { key: 'crtsh', label: 'Certificate transparency (crt.sh)', href: 'https://crt.sh', desc: 'Whether a lookalike already has a TLS certificate' },
      ]} counts={{ registered: last.registered, ...(last.phishing_feeds || {}), crtsh: last.registered !== undefined ? 'checked' : undefined }} unit="" />
      <p className="fineprint">SecYourScan never opens these sites. Investigate them from an isolated browser. The takedown button drafts a request with the registrar's and hosting provider's abuse contacts on the Takedowns page.</p>
    </div>
  );
}
