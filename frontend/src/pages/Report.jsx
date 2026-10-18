import React, { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { BadgeCheck, CircleCheck, CircleX, Download, FileText, Lock } from 'lucide-react';
import { api } from '../api';
import { Card, Empty, ErrorBox, Pill, SeverityBadge, Spinner, relTime, useAsync, useToast } from '../components/ui';

const LEVEL_TONE = { critical: 'critical', high: 'warn', moderate: 'warn', low: 'ok' };

export default function Report() {
  const [params, setParams] = useSearchParams();
  const doms = useAsync(() => api.reportDomains(), []);
  const allowed = (doms.data || []).filter((d) => d.allowed);
  const domain = params.get('domain') || allowed[0]?.domain || '';
  const rep = useAsync(() => (domain ? api.domainReport(domain) : Promise.resolve(null)), [domain]);
  const [downloading, setDownloading] = useState(false);
  const toast = useToast();

  useEffect(() => {
    if (!params.get('domain') && allowed[0]) setParams({ domain: allowed[0].domain }, { replace: true });
  }, [allowed, params, setParams]);

  const download = async () => {
    setDownloading(true);
    try {
      await api.domainReportPdf(domain);
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      setDownloading(false);
    }
  };

  const r = rep.data;
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Exposure Report</h1>
          <p className="muted">Everything SecYourScan knows about one root domain, with a risk score whose every point is explained. Export it as a PDF for stakeholders.</p>
        </div>
        <div className="btn-row">
          {allowed.length > 0 && (
            <select className="input" value={domain} onChange={(e) => setParams({ domain: e.target.value })} aria-label="Domain">
              {allowed.map((d) => <option key={d.domain} value={d.domain}>{d.domain}{d.verified ? ' ✓' : ''}</option>)}
            </select>
          )}
          <button className="btn btn-primary" onClick={download} disabled={!r || downloading}><Download size={14} /> {downloading ? 'Building…' : 'PDF'}</button>
        </div>
      </div>

      <ErrorBox error={doms.error || rep.error} onRetry={() => { doms.reload(); rep.reload(); }} />
      {doms.loading && !doms.data && <Spinner />}
      {doms.data && allowed.length === 0 && (
        <div className="card">
          <Empty title={doms.data.length ? 'No verified domain yet' : 'No domains yet'}>
            {doms.data.length
              ? <>Reports cover verified domains only. <Link className="link" to="/domains">Verify a domain</Link>.</>
              : <>Add your root domain on the <Link className="link" to="/watchlist">Watchlist</Link> and verify it on <Link className="link" to="/domains">Domains</Link>.</>}
          </Empty>
        </div>
      )}
      {rep.loading && !r && domain && <Spinner label="Building report…" />}

      {r && (
        <>
          <section className={`report-hero lvl-${r.level}`}>
            <div className="report-score">
              <div className="report-num">{r.score}</div>
              <div className="faint small">of 100</div>
            </div>
            <div className="report-hero-main">
              <div className="report-domain">
                {r.domain} {(doms.data || []).find((d) => d.domain === r.domain)?.verified && <Pill tone="ok"><BadgeCheck size={12} /> verified</Pill>}
              </div>
              <div><Pill tone={LEVEL_TONE[r.level]}>{r.level} risk</Pill> <span className="faint small">generated {relTime(r.generated_at)}</span></div>
              {r.factors.length === 0 ? (
                <p className="small muted mt">No risk factors found in the collected data.</p>
              ) : (
                <ul className="factor-list">
                  {r.factors.map((f) => (
                    <li key={f.factor}>
                      <span className="factor-name">{f.factor} <span className="faint">× {f.count}</span></span>
                      <span className="factor-track"><span style={{ width: `${(f.points / 40) * 100}%` }} /></span>
                      <span className="factor-pts">+{f.points}<span className="faint"> / {f.cap}</span></span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </section>

          <div className="dash-row even">
            <Card title="Attack surface" actions={<Link className="link small" to="/surface">Details</Link>}>
              <div className="mini-stats" style={{ marginTop: 0 }}>
                <Stat label="Hosts" value={r.surface.hosts} sub={`${r.surface.live} live`} />
                <Stat label="Critical/high ports" value={r.surface.critical_ports.length} bad={r.surface.critical_ports.length} />
                <Stat label="Threat-feed listings" value={r.surface.listed} bad={r.surface.listed} />
              </div>
              <div className="mini-stats">
                <Stat label="TLS graded" value={r.surface.tls.graded} sub={Object.entries(r.surface.tls.distribution).sort().map(([g, n]) => `${g}:${n}`).join(' ') || '—'} />
                <Stat label="TLS D/F" value={r.surface.tls.failing} bad={r.surface.tls.failing} />
                <Stat label="Certs ≤ 30d" value={r.surface.certs_expiring} bad={r.surface.certs_expiring} />
              </div>
              {r.surface.critical_ports.length > 0 && (
                <ul className="plain-list mt">
                  {r.surface.critical_ports.slice(0, 6).map((p) => (
                    <li key={`${p.hostname}:${p.port}`} className="small"><Pill tone={p.risk === 'critical' ? 'critical' : 'warn'}>{p.risk}</Pill> {p.hostname}:{p.port} · {p.service}</li>
                  ))}
                </ul>
              )}
            </Card>
            <Card title="Email & DNS security" actions={<Link className="link small" to="/surface?tab=dns">Details</Link>}>
              {r.surface.dns_checks.length === 0 ? <Empty title="Not checked yet" /> : (
                <ul className="posture">
                  {r.surface.dns_checks.map((c) => (
                    <li key={c.check} className={c.ok ? 'ok' : `bad-${c.severity}`}>
                      {c.ok ? <CircleCheck size={15} /> : <CircleX size={15} />}
                      <div><div className="posture-name">{c.check}</div><div className="sub posture-detail">{c.detail}</div></div>
                    </li>
                  ))}
                </ul>
              )}
            </Card>
          </div>

          <div className="dash-row even">
            <Card title="Vulnerabilities" actions={<Link className="link small" to="/vulns">Details</Link>}>
              <div className="mini-stats" style={{ marginTop: 0 }}>
                <Stat label="Open" value={r.vulns.open} />
                <Stat label="KEV" value={r.vulns.by_priority.critical} bad={r.vulns.by_priority.critical} />
                <Stat label="High EPSS" value={r.vulns.by_priority.high} bad={r.vulns.by_priority.high} />
              </div>
              {r.vulns.top.length > 0 && (
                <ul className="plain-list mt">
                  {r.vulns.top.slice(0, 6).map((v) => (
                    <li key={`${v.host}-${v.cve}`} className="small"><Pill tone={v.priority === 'critical' ? 'critical' : 'default'}>{v.priority}</Pill> <span className="mono">{v.cve}</span> · {v.host}</li>
                  ))}
                </ul>
              )}
            </Card>
            <Card title="Brand & threats" actions={<Link className="link small" to="/brand">Details</Link>}>
              <div className="mini-stats" style={{ marginTop: 0 }}>
                <Stat label="Lookalikes" value={r.brand.lookalikes} sub={`${r.brand.high_risk} high risk`} bad={r.brand.high_risk} />
                <Stat label="Live phishing" value={r.brand.phishing_live} bad={r.brand.phishing_live} />
                <Stat label="Ransomware" value={r.ransomware.length} bad={r.ransomware.length} />
              </div>
              {r.ransomware.map((h) => (
                <div key={`${h.group}-${h.victim}`} className="rw-mini"><Lock size={13} /> Listed by <b>{h.group}</b> as “{h.victim}”</div>
              ))}
            </Card>
          </div>

          <Card title={`Leak mentions · last ${r.leaks.window_days} days`} actions={<Link className="link small" to="/leaks">Leaks</Link>}>
            {r.leaks.total === 0 ? <Empty title="No leak mentions of this domain's watched assets" /> : (
              <>
                <div className="tags mb">{Object.entries(r.leaks.by_source).map(([s, n]) => <Pill key={s}>{s} · {n}</Pill>)}</div>
                {r.leaks.top.map((l) => (
                  <Link key={l.id} className="stream-row plain" to={`/leaks?id=${encodeURIComponent(l.id)}`}>
                    <SeverityBadge value={l.severity} />
                    <div className="list-main"><div className="list-title">{l.title}</div><div className="list-sub">{l.source} · {relTime(l.discovered_at)}</div></div>
                    <Pill>{l.status}</Pill>
                  </Link>
                ))}
              </>
            )}
          </Card>
          <p className="fineprint"><FileText size={11} /> Built from data SecYourScan has already collected; nothing is fetched when the report opens. Leak content is never included, only titles, sources and severities.</p>
        </>
      )}
    </div>
  );
}

function Stat({ label, value, sub, bad }) {
  return (
    <div className="mini-stat">
      <div className="lbl">{label}</div>
      <div className="val" style={{ color: bad ? 'var(--crit)' : undefined }}>{value}</div>
      {sub && <div className="lbl">{sub}</div>}
    </div>
  );
}
