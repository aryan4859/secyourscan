import React, { useCallback, useState } from 'react';
import { ExternalLink, Skull } from 'lucide-react';
import { api } from '../api';
import ScanBar from '../components/ScanBar';
import { Empty, ErrorBox, Pill, Spinner, relTime, useAsync, useToast } from '../components/ui';
import { Tile } from './Surface';

const PRIORITY_TONE = { critical: 'critical', high: 'warn', medium: 'default', low: 'default' };
const TABS = ['open', 'accepted', 'fixed'];

export default function Vulns() {
  const [tab, setTab] = useState('open');
  const list = useAsync(() => api.vulns(tab), [tab]);
  const toast = useToast();
  const reload = useCallback(() => list.reload(), [list.reload]);
  const rows = list.data || [];

  const setStatus = async (f, status) => {
    try {
      await api.updateVuln(f.id, status);
      list.setData((xs) => xs.filter((x) => x.id !== f.id));
      toast(status === 'accepted' ? `${f.cve} on ${f.host}: risk accepted` : `${f.cve} reopened`, 'ok');
    } catch (e) {
      toast(e.message, 'error');
    }
  };

  const count = (p) => rows.filter((f) => f.priority === p).length;
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Vulnerabilities</h1>
          <p className="muted">CVEs that Shodan sees on your exposed hosts and watched IPs, ranked by whether attackers are exploiting them now (CISA KEV) and how likely they are to (FIRST EPSS, next 30 days).</p>
        </div>
        <ScanBar module="vulns" label="Vulnerability" onFinished={reload} />
      </div>

      {tab === 'open' && (
        <div className="kpi-grid five">
          <Tile label="Open findings" value={rows.length} sub="host × CVE pairs" />
          <Tile label="Critical · KEV" value={count('critical')} sub="exploited in the wild" tone={count('critical') ? 'crit' : ''} />
          <Tile label="High" value={count('high')} sub="EPSS ≥ 50%" tone={count('high') ? 'warn' : ''} />
          <Tile label="Medium" value={count('medium')} sub="EPSS ≥ 10%" />
          <Tile label="Ransomware-linked" value={rows.filter((f) => f.kev_ransomware).length} sub="KEV: used in campaigns" tone={rows.some((f) => f.kev_ransomware) ? 'crit' : ''} />
        </div>
      )}

      <div className="tabs">
        {TABS.map((t) => <button key={t} className={t === tab ? 'on' : ''} onClick={() => setTab(t)}>{t}</button>)}
      </div>

      <ErrorBox error={list.error} onRetry={list.reload} />
      {list.loading && !list.data && <Spinner />}
      {list.data && rows.length === 0 && (
        <div className="card"><Empty title={tab === 'open' ? 'No open vulnerabilities found' : `Nothing ${tab}`}>
          {tab === 'open' && 'Findings come from the attack-surface scan and from IP addresses on your watchlist.'}
        </Empty></div>
      )}
      {rows.length > 0 && (
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Priority</th><th>CVE</th><th>Exploitation</th><th className="w-expo">EPSS (30-day probability)</th><th>Host</th><th>Seen</th><th /></tr></thead>
            <tbody>
              {rows.map((f) => (
                <tr key={f.id}>
                  <td><Pill tone={PRIORITY_TONE[f.priority]}>{f.priority}</Pill></td>
                  <td>
                    <a className="link mono" href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(f.cve)}`} target="_blank" rel="noreferrer noopener">
                      {f.cve} <ExternalLink size={11} />
                    </a>
                    {f.kev_name && <div className="sub">{f.kev_name}</div>}
                  </td>
                  <td>
                    <div className="tags">
                      {f.kev ? <Pill tone="critical">KEV · {f.kev_added}</Pill> : <span className="faint small">not in KEV</span>}
                      {f.kev_ransomware && <Pill tone="critical"><Skull size={11} /> ransomware</Pill>}
                    </div>
                  </td>
                  <td>
                    {f.epss != null ? (
                      <div className="expo" title={`EPSS ${(f.epss * 100).toFixed(1)}% · percentile ${(f.percentile * 100).toFixed(0)}`}>
                        <span className="expo-track"><span className="expo-fill" style={{ width: `${Math.max(f.epss * 100, 1)}%`, background: 'var(--series-1)' }} /></span>
                        <span className="expo-num" style={{ width: 44 }}>{(f.epss * 100).toFixed(f.epss < 0.1 ? 1 : 0)}%</span>
                      </div>
                    ) : <span className="faint small">no score</span>}
                  </td>
                  <td><div className="asset-name">{f.host}</div>{f.ip && f.ip !== f.host && <div className="sub mono">{f.ip}</div>}</td>
                  <td className="nowrap muted">{relTime(f.first_seen)}</td>
                  <td className="right">
                    {tab === 'open' && <button className="btn btn-sm" onClick={() => setStatus(f, 'accepted')}>Accept risk</button>}
                    {tab === 'accepted' && <button className="btn btn-sm" onClick={() => setStatus(f, 'open')}>Reopen</button>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="fineprint">Shodan InternetDB infers CVEs from service banners, so some may already be patched by backports. Verify before acting; mark those as "accept risk".</p>
    </div>
  );
}
