import React, { useCallback, useMemo, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  Bug, CircleCheck, CircleX, Globe, History, Lock, LockOpen, Network, Plug, Search, ShieldCheck, Siren,
} from 'lucide-react';
import { api } from '../api';
import ScanBar from '../components/ScanBar';
import SourcesPanel from '../components/SourcesPanel';
import { Empty, ErrorBox, Pill, Spinner, fmtDate, relTime, useAsync } from '../components/ui';

const TABS = [
  { key: 'hosts', label: 'Hosts', icon: Globe },
  { key: 'ports', label: 'Critical ports', icon: Plug },
  { key: 'tls', label: 'SSL/TLS', icon: ShieldCheck },
  { key: 'dns', label: 'DNS', icon: Network },
  { key: 'changes', label: 'Changes', icon: History },
];

const FILTERS = [
  { key: 'all', label: 'All' },
  { key: 'live', label: 'Live' },
  { key: 'new', label: 'New (7d)' },
  { key: 'cves', label: 'With CVEs' },
  { key: 'certs', label: 'Cert ≤ 30d' },
  { key: 'listed', label: 'In threat feeds' },
];

const DISCOVERY = [
  { key: 'crt.sh', label: 'Certificate transparency', href: 'https://crt.sh', desc: 'crt.sh and Cert Spotter: every hostname a public CA has issued a certificate for' },
  { key: 'hackertarget', label: 'HackerTarget passive DNS', href: 'https://hackertarget.com', desc: 'Historic DNS answers; finds hosts hidden behind wildcard certificates (50 free lookups a day)' },
  { key: 'wayback', label: 'Wayback Machine', href: 'https://web.archive.org', desc: 'Hostnames the Internet Archive has crawled' },
  { key: 'otx', label: 'AlienVault OTX passive DNS', href: 'https://otx.alienvault.com', desc: 'Needs a free OTX_API_KEY', off: 'no API key' },
  { key: 'dns', label: 'DNS name check', desc: '~170 common names (vpn, mail, ebanking…) resolved, wildcard answers ignored' },
];
const FEEDS = [
  { key: 'urlhaus', label: 'abuse.ch URLhaus', href: 'https://urlhaus.abuse.ch', desc: 'URLs serving malware right now: a match means a compromised server' },
  { key: 'feodo', label: 'abuse.ch Feodo Tracker', href: 'https://feodotracker.abuse.ch', desc: 'Botnet command-and-control IPs' },
  { key: 'threatfox', label: 'abuse.ch ThreatFox', href: 'https://threatfox.abuse.ch', desc: 'Recent IOCs: C2 servers, payload hosts, phishing' },
  { key: 'internetdb', label: 'Shodan InternetDB', href: 'https://internetdb.shodan.io', desc: 'Open ports, CPEs and CVEs of each public IP' },
];

const RISK_TONE = { critical: 'critical', high: 'warn', medium: 'default', low: 'default', info: 'default' };
const SEV_TONE = { critical: 'critical', warning: 'warn', info: 'default' };
const KIND_LABEL = {
  host_added: 'Host added', host_gone: 'Host gone', ip_changed: 'IP changed', port_opened: 'Port opened',
  port_closed: 'Port closed', cert_changed: 'Certificate replaced', dns_changed: 'DNS changed',
};

function certTone(days) {
  if (days == null) return null;
  if (days <= 14) return 'critical';
  if (days <= 30) return 'warn';
  return 'ok';
}

export default function Surface() {
  const [params, setParams] = useSearchParams();
  const tab = TABS.some((t) => t.key === params.get('tab')) ? params.get('tab') : 'hosts';
  const summary = useAsync(() => api.intelSummary(), []);
  const [tick, setTick] = useState(0);
  const navigate = useNavigate();
  const reload = useCallback(() => { summary.reload(); setTick((t) => t + 1); }, [summary.reload]);
  const s = summary.data?.surface;

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Attack Surface</h1>
          <p className="muted">Your digital footprint as an attacker sees it: every host under your domains, the ports and services it exposes, how well its TLS is configured, your DNS and email-security posture, and what changed since the last scan.</p>
        </div>
        <ScanBar module="surface" extraModule="vulns" label="Attack surface" onFinished={reload} />
      </div>

      <div className="kpi-grid five">
        <Tile label="Hostnames" value={s?.hosts} sub={s ? `${s.live} live · ${s.new_7d} new this week` : ''} onClick={() => setParams({ tab: 'hosts' })} />
        <Tile label="Critical ports" value={s?.critical_ports} sub="RDP, SMB, databases…" tone={s?.critical_ports ? 'crit' : ''} onClick={() => setParams({ tab: 'ports' })} />
        <Tile label="TLS grade D/F" value={s?.tls_failing} sub={s ? `${s.expiring_certs} cert(s) expire ≤ 30d` : ''} tone={s?.tls_failing ? 'crit' : s?.expiring_certs ? 'warn' : ''} onClick={() => setParams({ tab: 'tls' })} />
        <Tile label="DNS posture issues" value={s?.dns_failing} sub="SPF · DMARC · NS" tone={s?.dns_failing ? 'crit' : ''} onClick={() => setParams({ tab: 'dns' })} />
        <Tile label="In threat feeds" value={s?.listed} sub="URLhaus · Feodo · ThreatFox" tone={s?.listed ? 'crit' : ''} onClick={() => setParams({ tab: 'hosts' })} />
      </div>

      <div className="tabs" role="tablist">
        {TABS.map((t) => (
          <button key={t.key} role="tab" aria-selected={t.key === tab} className={t.key === tab ? 'on' : ''} onClick={() => setParams({ tab: t.key })}>
            <t.icon size={14} /> {t.label}
          </button>
        ))}
      </div>

      {tab === 'hosts' && <HostsTab key={tick} navigate={navigate} />}
      {tab === 'ports' && <PortsTab key={tick} />}
      {tab === 'tls' && <TlsTab key={tick} />}
      {tab === 'dns' && <DnsTab key={tick} />}
      {tab === 'changes' && <ChangesTab key={tick} />}
    </div>
  );
}

// ── Hosts ────────────────────────────────────────────────────────────────────

function HostsTab({ navigate }) {
  const hosts = useAsync(() => api.surfaceHosts(), []);
  const status = useAsync(() => api.intelStatus(), []);
  const [filter, setFilter] = useState('all');
  const [q, setQ] = useState('');
  const [root, setRoot] = useState('');
  const rows = hosts.data || [];
  const roots = useMemo(() => [...new Set(rows.map((h) => h.root_domain))], [rows]);
  const shown = rows.filter((h) => (!root || h.root_domain === root)
    && (!q.trim() || h.hostname.includes(q.trim().toLowerCase()) || h.ips.some((ip) => ip.includes(q.trim())))
    && (filter === 'all' || (filter === 'live' && h.resolves) || (filter === 'new' && h.is_new)
      || (filter === 'cves' && h.cves.length) || (filter === 'certs' && h.tls_days_left != null && h.tls_days_left <= 30)
      || (filter === 'listed' && h.threats.length)));
  const last = status.data?.surface?.result || {};

  return (
    <>
      <div className="topo-toolbar">
        <div className="seg" role="group" aria-label="Filter hosts">
          {FILTERS.map((f) => <button key={f.key} className={f.key === filter ? 'on' : ''} onClick={() => setFilter(f.key)}>{f.label}</button>)}
        </div>
        {roots.length > 1 && (
          <select className="input" value={root} onChange={(e) => setRoot(e.target.value)} aria-label="Root domain">
            <option value="">All domains</option>
            {roots.map((r) => <option key={r} value={r}>{r}</option>)}
          </select>
        )}
        <label className="topo-search"><Search size={14} />
          <input className="input bare" placeholder="Filter by hostname or IP…" value={q} onChange={(e) => setQ(e.target.value)} />
        </label>
      </div>

      <ErrorBox error={hosts.error} onRetry={hosts.reload} />
      {hosts.loading && !hosts.data && <Spinner />}
      {hosts.data && rows.length === 0 && (
        <div className="card"><Empty title="No attack surface mapped yet">Add your domains on the Watchlist, then run a scan.</Empty></div>
      )}
      {rows.length > 0 && (
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Hostname</th><th>Addresses</th><th>Open ports</th><th>CVEs</th><th>TLS certificate</th><th>First seen</th></tr></thead>
            <tbody>
              {shown.map((h) => {
                const tone = certTone(h.tls_days_left);
                return (
                  <tr key={h.id} className={h.resolves ? '' : 'dim'}>
                    <td>
                      <div className="asset-id">
                        <span className="asset-icon"><Globe size={14} /></span>
                        <span>
                          <div className="asset-name">{h.hostname} {h.is_new && <Pill tone="warn">new</Pill>}</div>
                          <div className="sub">{h.resolves ? 'via ' : 'does not resolve · via '}{h.sources.join(', ') || '—'}</div>
                          {h.threats.length > 0 && (
                            <div className="tags mt-xs">
                              {h.threats.map((t) => (
                                <Pill key={`${t.feed}-${t.indicator}`} tone="critical" title={t.indicator}>
                                  <Siren size={11} /> {t.feed}{t.malware ? ` · ${t.malware}` : ''}
                                </Pill>
                              ))}
                            </div>
                          )}
                        </span>
                      </div>
                    </td>
                    <td className="mono small">{h.ips.length ? h.ips.join(', ') : '—'}</td>
                    <td><div className="tags">{h.ports.length ? h.ports.map((p) => <Pill key={p}>{p}</Pill>) : <span className="faint">—</span>}</div></td>
                    <td>
                      {h.cves.length ? (
                        <button className="chip chip-critical on" onClick={() => navigate('/vulns')}><Bug size={12} /> {h.cves.length}</button>
                      ) : <span className="faint">—</span>}
                    </td>
                    <td>
                      {h.tls_not_after ? (
                        <span className={`cert cert-${tone}`} title={`Issued by ${h.tls_issuer} · expires ${fmtDate(h.tls_not_after)}`}>
                          {tone === 'ok' ? <Lock size={13} /> : <LockOpen size={13} />}
                          {h.tls_days_left < 0 ? `expired ${-h.tls_days_left}d ago` : `${h.tls_days_left}d left`}
                          <span className="faint"> · {h.tls_issuer}</span>
                        </span>
                      ) : <span className="faint">{h.resolves ? 'no TLS on 443' : '—'}</span>}
                    </td>
                    <td className="nowrap muted">{relTime(h.first_seen)}</td>
                  </tr>
                );
              })}
              {shown.length === 0 && <tr><td colSpan={6}><Empty title="No host matches these filters" /></td></tr>}
            </tbody>
          </table>
        </div>
      )}
      <div className="dash-row even">
        <SourcesPanel title="Discovery sources" sources={DISCOVERY} counts={last.source_status || last.sources} unit="hosts" />
        <SourcesPanel title="Threat & exposure feeds" sources={FEEDS} counts={{ ...(last.feeds || {}), internetdb: last.ips }} unit="entries" />
      </div>
    </>
  );
}

// ── Critical ports ───────────────────────────────────────────────────────────

function PortsTab() {
  const ports = useAsync(() => api.surfacePorts(), []);
  const [risk, setRisk] = useState('all');
  const rows = ports.data || [];
  const counts = rows.reduce((c, r) => ({ ...c, [r.risk]: (c[r.risk] || 0) + 1 }), {});
  const shown = rows.filter((r) => risk === 'all' || r.risk === risk);
  return (
    <>
      <div className="topo-toolbar">
        <div className="seg" role="group" aria-label="Risk">
          {['all', 'critical', 'high', 'medium', 'low', 'info'].map((r) => (
            <button key={r} className={r === risk ? 'on' : ''} onClick={() => setRisk(r)}>
              {r === 'all' ? 'All' : r} {r !== 'all' && <span className="faint">{counts[r] || 0}</span>}
            </button>
          ))}
        </div>
      </div>
      <ErrorBox error={ports.error} onRetry={ports.reload} />
      {ports.loading && !ports.data && <Spinner />}
      {ports.data && rows.length === 0 && <div className="card"><Empty title="No exposed ports recorded">Ports come from Shodan InternetDB for each live host's public IP.</Empty></div>}
      {ports.data && rows.length > 0 && !counts.critical && (
        <div className="rw-clear"><CircleCheck size={18} /><div><b>No critical service is exposed.</b><div className="small muted">No RDP, SMB, Telnet, database, Docker, Redis or Elasticsearch port on any live host.</div></div></div>
      )}
      {shown.length > 0 && (
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Risk</th><th>Port</th><th>Service</th><th>Host</th><th>Why it matters</th></tr></thead>
            <tbody>
              {shown.map((r) => (
                <tr key={`${r.hostname}:${r.port}`}>
                  <td><Pill tone={RISK_TONE[r.risk]}>{r.risk}</Pill></td>
                  <td className="mono">{r.port}</td>
                  <td>{r.service}</td>
                  <td><div className="asset-name">{r.hostname}</div><div className="sub mono">{r.ips.join(', ')}</div></td>
                  <td className="muted small">{r.why || 'Not on the critical-service list'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="fineprint">Ports come from Shodan's existing internet-wide scan data; SecYourScan does not port-scan. Opening a critical port raises a critical alert.</p>
    </>
  );
}

// ── SSL/TLS ──────────────────────────────────────────────────────────────────

function GradeBadge({ grade }) {
  return <span className={`grade grade-${grade}`} title={`TLS grade ${grade}`}>{grade}</span>;
}

function TlsTab() {
  const tls = useAsync(() => api.surfaceTls(), []);
  const rows = tls.data || [];
  const dist = rows.reduce((c, g) => ({ ...c, [g.grade]: (c[g.grade] || 0) + 1 }), {});
  return (
    <>
      <ErrorBox error={tls.error} onRetry={tls.reload} />
      {tls.loading && !tls.data && <Spinner />}
      {tls.data && rows.length === 0 && <div className="card"><Empty title="No TLS endpoints graded yet">Every live host answering TLS on port 443 is graded during the attack-surface scan.</Empty></div>}
      {rows.length > 0 && (
        <>
          <div className="grade-dist">
            {['A', 'B', 'C', 'D', 'F'].map((g) => (
              <div key={g} className="grade-cell"><GradeBadge grade={g} /><b>{dist[g] || 0}</b><span className="faint small">host{dist[g] === 1 ? '' : 's'}</span></div>
            ))}
          </div>
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Grade</th><th>Host</th><th>Protocol</th><th>Certificate</th><th>Key · signature</th><th>Findings</th></tr></thead>
              <tbody>
                {rows.map((g) => {
                  const d = g.details || {};
                  const days = d.not_after ? Math.floor((new Date(`${d.not_after}Z`) - Date.now()) / 86400000) : null;
                  return (
                    <tr key={g.hostname}>
                      <td><GradeBadge grade={g.grade} /></td>
                      <td><div className="asset-name">{g.hostname}</div><div className="sub">checked {relTime(g.checked_at)}</div></td>
                      <td>
                        <div className="mono small">{d.protocol}</div>
                        <div className="tags mt-xs">
                          {d.tls10 && <Pill tone="warn">TLS 1.0</Pill>}
                          {d.tls11 && <Pill tone="warn">TLS 1.1</Pill>}
                        </div>
                      </td>
                      <td>
                        <div className={`cert cert-${certTone(days)}`}>{days == null ? '—' : days < 0 ? `expired ${-days}d ago` : `${days}d left`}</div>
                        <div className="sub" title={d.issuer}>{(d.issuer || '').match(/O=([^,]+)/)?.[1] || d.issuer}</div>
                      </td>
                      <td className="small"><span className="mono">{d.key_type} {d.key_bits || ''}</span><div className="sub">{d.sig_alg}</div></td>
                      <td>
                        {g.issues.length === 0 ? <span className="chain-ok small"><CircleCheck size={13} /> no issues</span> : (
                          <ul className="issue-list">
                            {g.issues.map((i) => (
                              <li key={i.text} className={`iss-${i.level}`}>{i.level === 'info' ? <CircleCheck size={12} /> : <CircleX size={12} />} {i.text}</li>
                            ))}
                          </ul>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </>
      )}
      <p className="fineprint">Grades follow the SSL Labs idea of caps: one serious flaw (untrusted, expired, wrong host, weak key) means F; legacy TLS 1.0/1.1 caps at C; TLS 1.2 without 1.3 is B.</p>
    </>
  );
}

// ── DNS ──────────────────────────────────────────────────────────────────────

function DnsTab() {
  const dns = useAsync(() => api.surfaceDns(), []);
  return (
    <>
      <ErrorBox error={dns.error} onRetry={dns.reload} />
      {dns.loading && !dns.data && <Spinner />}
      {dns.data?.length === 0 && <div className="card"><Empty title="No DNS data yet">Watched domains are checked during the attack-surface scan.</Empty></div>}
      {dns.data?.map((d) => (
        <section key={d.domain} className="card">
          <header className="card-head"><h2><Network size={15} /> {d.domain}</h2></header>
          <div className="card-body dns-grid">
            <div>
              <h4>Email & DNS security</h4>
              <ul className="posture">
                {d.checks.map((c) => (
                  <li key={c.check} className={c.ok ? 'ok' : `bad-${c.severity}`}>
                    {c.ok ? <CircleCheck size={15} /> : <CircleX size={15} />}
                    <div><div className="posture-name">{c.check}</div><div className="sub posture-detail">{c.detail}</div></div>
                  </li>
                ))}
              </ul>
            </div>
            <div>
              <h4>Records</h4>
              <table className="table compact">
                <tbody>
                  {['A', 'AAAA', 'MX', 'NS', 'TXT', 'CAA'].map((rt) => {
                    const r = d.records[rt];
                    return (
                      <tr key={rt}>
                        <td className="mono" style={{ width: 60 }}>{rt}</td>
                        <td className="mono small dns-values">{r?.values?.length ? r.values.join('\n') : <span className="faint">—</span>}</td>
                        <td className="nowrap faint small">{r ? `changed ${relTime(r.changed_at)}` : ''}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </section>
      ))}
      <p className="fineprint">A change to NS or MX records raises a critical alert: it can mean the domain or its mail has been hijacked.</p>
    </>
  );
}

// ── Changes ──────────────────────────────────────────────────────────────────

function ChangesTab() {
  const ev = useAsync(() => api.surfaceEvents(), []);
  const [sev, setSev] = useState('all');
  const rows = (ev.data || []).filter((e) => sev === 'all' || e.severity === sev);
  return (
    <>
      <div className="topo-toolbar">
        <div className="seg" role="group" aria-label="Severity">
          {['all', 'critical', 'warning', 'info'].map((s) => <button key={s} className={s === sev ? 'on' : ''} onClick={() => setSev(s)}>{s === 'all' ? 'All' : s}</button>)}
        </div>
      </div>
      <ErrorBox error={ev.error} onRetry={ev.reload} />
      {ev.loading && !ev.data && <Spinner />}
      {ev.data && ev.data.length === 0 && (
        <div className="card"><Empty title="No changes recorded yet">The first scan sets the baseline; later scans log hosts appearing or disappearing, IP and port changes, replaced certificates and DNS changes.</Empty></div>
      )}
      {rows.length > 0 && (
        <ul className="timeline-list">
          {rows.map((e) => (
            <li key={e.id} className={`tl-${e.severity}`}>
              <span className="tl-dot" />
              <div className="tl-main">
                <div className="tl-head">
                  <Pill tone={SEV_TONE[e.severity]}>{KIND_LABEL[e.kind] || e.kind}</Pill>
                  <b className="mono small">{e.subject}</b>
                  <span className="faint small" title={fmtDate(e.at)}>{relTime(e.at)}</span>
                </div>
                <div className="tl-detail">{e.detail}</div>
              </div>
            </li>
          ))}
        </ul>
      )}
    </>
  );
}

export function Tile({ label, value, sub, tone = '', onClick }) {
  return (
    <div className={`kpi ${onClick ? 'clickable' : ''} ${tone ? `kpi-${tone}` : ''}`} onClick={onClick}>
      <div className="kpi-head"><span>{label}</span></div>
      <div className="kpi-value">{value ?? '—'}</div>
      <div className="kpi-sub">{sub}</div>
    </div>
  );
}
