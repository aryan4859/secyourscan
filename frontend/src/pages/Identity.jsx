import React, { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { AppWindow, Bug, Crown, KeyRound, Laptop, Repeat, Search, UserRound } from 'lucide-react';
import { api } from '../api';
import { Card, Drawer, Empty, ErrorBox, KV, Pill, SeverityBadge, Spinner, fmtDate, relTime, useAsync } from '../components/ui';
import useDebounced from '../useDebounced';
import { Tile } from './Surface';

const TABS = [
  { key: 'identities', label: 'Identities', icon: UserRound },
  { key: 'machines', label: 'Infected machines', icon: Laptop },
  { key: 'insights', label: 'Insights', icon: AppWindow },
];
const KINDS = [
  { key: 'all', label: 'All' },
  { key: 'stealer', label: 'Stealer-infected' },
  { key: 'corporate', label: 'Corporate apps' },
  { key: 'vip', label: 'VIP' },
  { key: 'reused', label: 'Password reuse' },
];

export function RiskMeter({ value }) {
  const band = value >= 80 ? 'critical' : value >= 60 ? 'high' : value >= 30 ? 'medium' : 'low';
  return (
    <span className={`risk-meter risk-${band}`} title={`Risk ${value} (${band})`}>
      <span className="risk-track"><span className="risk-fill" style={{ width: `${value}%` }} /></span>
      <span className="risk-num">{value}</span>
    </span>
  );
}

export default function Identity() {
  const [params, setParams] = useSearchParams();
  const tab = TABS.some((t) => t.key === params.get('tab')) ? params.get('tab') : 'identities';
  const summary = useAsync(() => api.identitySummary(), []);
  const s = summary.data;

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Identity &amp; Access Intelligence</h1>
          <p className="muted">Every account of yours that turned up in a leak: how the credential was stolen (infostealer malware or a combo list), which of your apps it opens, which infected machine it came from, and whether the same password is used elsewhere. Passwords are never shown, only masked.</p>
        </div>
      </div>

      <ErrorBox error={summary.error} onRetry={summary.reload} />
      <div className="kpi-grid five">
        <Tile label="Exposed identities" value={s?.identities} sub={s ? `${s.open} still open` : ''} onClick={() => setParams({ tab: 'identities' })} />
        <Tile label="Stealer-infected" value={s?.stealer_infected} sub="credentials taken from a device" tone={s?.stealer_infected ? 'crit' : ''} onClick={() => setParams({ tab: 'identities', kind: 'stealer' })} />
        <Tile label="Corporate app accounts" value={s?.corporate_app_accounts} sub="VPN, mail, SSO on your domains" tone={s?.corporate_app_accounts ? 'crit' : ''} onClick={() => setParams({ tab: 'identities', kind: 'corporate' })} />
        <Tile label="Infected machines" value={s?.machines} sub="distinct HWIDs / hosts" tone={s?.machines ? 'warn' : ''} onClick={() => setParams({ tab: 'machines' })} />
        <Tile label="Password reuse" value={s?.reused_passwords} sub={s ? `${s.vip} VIP account(s)` : ''} tone={s?.reused_passwords ? 'warn' : ''} onClick={() => setParams({ tab: 'identities', kind: 'reused' })} />
      </div>

      <div className="tabs" role="tablist">
        {TABS.map((t) => (
          <button key={t.key} role="tab" aria-selected={t.key === tab} className={t.key === tab ? 'on' : ''} onClick={() => setParams({ tab: t.key })}>
            <t.icon size={14} /> {t.label}
          </button>
        ))}
      </div>

      {tab === 'identities' && <IdentitiesTab kind={KINDS.some((k) => k.key === params.get('kind')) ? params.get('kind') : 'all'}
        setKind={(k) => setParams({ tab: 'identities', kind: k })} />}
      {tab === 'machines' && <MachinesTab />}
      {tab === 'insights' && <InsightsTab s={s} />}
    </div>
  );
}

function IdentitiesTab({ kind, setKind }) {
  const [q, setQ] = useState('');
  const dq = useDebounced(q, 250);
  const rows = useAsync(() => api.identities({ kind, q: dq || undefined }), [kind, dq]);
  const [open, setOpen] = useState(null);

  return (
    <>
      <div className="topo-toolbar">
        <div className="seg" role="group" aria-label="Filter identities">
          {KINDS.map((k) => <button key={k.key} className={k.key === kind ? 'on' : ''} onClick={() => setKind(k.key)}>{k.label}</button>)}
        </div>
        <label className="topo-search"><Search size={14} />
          <input className="input bare" placeholder="Filter by login or app…" value={q} onChange={(e) => setQ(e.target.value)} />
        </label>
      </div>
      <ErrorBox error={rows.error} onRetry={rows.reload} />
      {rows.loading && !rows.data && <Spinner />}
      {rows.data && rows.data.length === 0 && (
        <div className="card"><Empty title="No exposed identity">Add your domains and staff emails to the Watchlist; leaked accounts on them appear here.</Empty></div>
      )}
      {rows.data?.length > 0 && (
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Identity</th><th>Risk</th><th>How exposed</th><th>Apps</th><th>Machines</th><th>Exposures</th><th>Last seen</th></tr></thead>
            <tbody>
              {rows.data.map((i) => (
                <tr key={i.login} className="clickable" onClick={() => setOpen(i.login)}>
                  <td>
                    <div className="asset-id">
                      <span className="asset-icon">{i.vip ? <Crown size={14} /> : <UserRound size={14} />}</span>
                      <span>
                        <div className="asset-name mono">{i.login}</div>
                        <div className="sub">{i.executive ? `${i.executive} · ` : ''}{i.domain || 'app account'}</div>
                      </span>
                    </div>
                  </td>
                  <td><RiskMeter value={i.risk} /></td>
                  <td>
                    <div className="tags">
                      {i.stealer ? <Pill tone="critical"><Bug size={11} /> stealer{i.families.length ? ` · ${i.families.join(', ')}` : ''}</Pill> : <Pill>combo list</Pill>}
                      {i.reused && <Pill tone="warn"><Repeat size={11} /> reuse</Pill>}
                      {i.vip && <Pill tone="vip">VIP</Pill>}
                      {!i.open && <Pill tone="ok">handled</Pill>}
                    </div>
                  </td>
                  <td>
                    <div className="tags">
                      {i.corporate_apps.slice(0, 3).map((a) => <Pill key={a} tone="critical">{a}</Pill>)}
                      {i.apps.filter((a) => !i.corporate_apps.includes(a)).slice(0, 2).map((a) => <Pill key={a}>{a}</Pill>)}
                      {i.apps.length > 5 && <span className="faint small">+{i.apps.length - 5}</span>}
                      {i.apps.length === 0 && <span className="faint">—</span>}
                    </div>
                  </td>
                  <td>{i.machines || <span className="faint">—</span>}</td>
                  <td>{i.exposures}</td>
                  <td className="nowrap muted">{relTime(i.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {open && <IdentityDrawer login={open} onClose={() => setOpen(null)} />}
    </>
  );
}

function IdentityDrawer({ login, onClose }) {
  const d = useAsync(() => api.identity(login), [login]);
  const i = d.data;
  return (
    <Drawer title={login} onClose={onClose}>
      <ErrorBox error={d.error} onRetry={d.reload} />
      {d.loading && !i && <Spinner />}
      {i && (
        <>
          <div className="id-head">
            <RiskMeter value={i.risk} />
            <div className="tags">
              {i.stealer && <Pill tone="critical">infostealer</Pill>}
              {i.families.map((f) => <Pill key={f} tone="critical">{f}</Pill>)}
              {i.reused && <Pill tone="warn">password reuse</Pill>}
              {i.vip && <Pill tone="vip">VIP{i.executive ? ` · ${i.executive}` : ''}</Pill>}
            </div>
          </div>
          <Card title="What to do">
            <ol className="actions-list">{i.actions.map((a) => <li key={a}>{a}</li>)}</ol>
          </Card>
          <Card title="Exposure">
            <KV rows={[
              ['First seen', fmtDate(i.first_seen)],
              ['Last seen', fmtDate(i.last_seen)],
              ['Corporate apps', i.corporate_apps.length ? i.corporate_apps.join(', ') : 'none'],
              ['Other apps', i.apps.filter((a) => !i.corporate_apps.includes(a)).join(', ') || 'none'],
              ['Infected machines', i.machine_ids.length ? i.machine_ids.join(', ') : 'none'],
              ['Passwords seen', i.passwords.length ? <span className="mono">{i.passwords.join('   ')}</span> : '—'],
              ['Distinct passwords', i.distinct_passwords ?? 'unknown (older data)'],
              i.shared_with.length > 0 && ['Same password as', <span className="mono">{i.shared_with.join(', ')}</span>],
            ]} />
          </Card>
          <Card title={`Timeline (${i.timeline.length})`}>
            {i.timeline.map((e) => (
              <div key={`${e.leak_id}-${e.app}`} className="list-row">
                <SeverityBadge value={e.severity} />
                <div className="list-main">
                  <div className="list-title">{e.title}</div>
                  <div className="list-sub">
                    <Pill tone={e.kind === 'stealer' ? 'critical' : 'default'}>{e.kind}</Pill>
                    {e.app && <span className="mono">{e.app}</span>}
                    <span>via {e.source}</span>
                    {e.password && <span className="mono">pw {e.password}</span>}
                  </div>
                </div>
                <span className="faint small nowrap">{relTime(e.at)}</span>
              </div>
            ))}
          </Card>
        </>
      )}
    </Drawer>
  );
}

function MachinesTab() {
  const rows = useAsync(() => api.identityMachines(), []);
  return (
    <>
      <ErrorBox error={rows.error} onRetry={rows.reload} />
      {rows.loading && !rows.data && <Spinner />}
      {rows.data && rows.data.length === 0 && (
        <div className="card"><Empty title="No infected machine seen">Stealer logs that hold your accounts list the machine they came from; none so far.</Empty></div>
      )}
      {rows.data?.length > 0 && (
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Machine</th><th>Malware</th><th>Location</th><th>Your accounts on it</th><th>Corporate apps</th><th>Last seen</th></tr></thead>
            <tbody>
              {rows.data.map((m) => (
                <tr key={m.id}>
                  <td>
                    <div className="asset-id">
                      <span className="asset-icon"><Laptop size={14} /></span>
                      <span>
                        <div className="asset-name">{m.computer || 'unnamed machine'}</div>
                        <div className="sub mono">{m.hwid ? `HWID ${m.hwid}` : 'no HWID in log'}{m.os ? ` · ${m.os}` : ''}</div>
                      </span>
                    </div>
                  </td>
                  <td>{m.family ? <Pill tone="critical"><Bug size={11} /> {m.family}</Pill> : <span className="faint">unknown</span>}</td>
                  <td className="small">{[m.ip, m.country].filter(Boolean).join(' · ') || <span className="faint">—</span>}</td>
                  <td><div className="tags">{m.logins.slice(0, 4).map((l) => <Pill key={l}><KeyRound size={11} /> {l}</Pill>)}{m.accounts > 4 && <span className="faint small">+{m.accounts - 4}</span>}</div></td>
                  <td><div className="tags">{m.corporate_apps.length ? m.corporate_apps.map((a) => <Pill key={a} tone="critical">{a}</Pill>) : <span className="faint">—</span>}</div></td>
                  <td className="nowrap muted">{relTime(m.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

function Bars({ rows, label, value, tone }) {
  const max = Math.max(1, ...rows.map(value));
  return (
    <ul className="src-bars">
      {rows.map((r) => (
        <li key={label(r)} style={{ gridTemplateColumns: 'minmax(90px, 200px) 1fr 40px' }}>
          <span className="src-name" title={label(r)}>{label(r)}</span>
          <span className="src-track"><span className={`src-fill ${tone?.(r) || ''}`} style={{ width: `${(value(r) / max) * 100}%` }} /></span>
          <span className="src-num">{value(r)}</span>
        </li>
      ))}
    </ul>
  );
}

function InsightsTab({ s }) {
  if (!s) return <Spinner />;
  return (
    <>
      <div className="dash-row even">
        <Card title="Apps with leaked accounts">
          {s.top_apps.length === 0 ? <Empty title="None yet" /> : (
            <Bars rows={s.top_apps} label={(r) => r.host} value={(r) => r.accounts} tone={(r) => (r.corporate ? 'src-bad' : '')} />
          )}
          <div className="fineprint">Red bars are apps on your own domains: those accounts open your network.</div>
        </Card>
        <Card title="Stealer families">
          {s.families.length === 0 ? <Empty title="No stealer logs" /> : (
            <Bars rows={s.families} label={(r) => r.family} value={(r) => r.logs} />
          )}
          <div className="fineprint">Detected from the log's own banner and file names.</div>
        </Card>
      </div>
      <div className="dash-row even">
        <Card title="Risk distribution">
          <Bars rows={Object.entries(s.bands).map(([band, n]) => ({ band, n }))} label={(r) => r.band} value={(r) => r.n} />
        </Card>
        <Card title="Shared passwords">
          {s.shared_passwords.length === 0 ? <Empty title="No password shared between accounts" /> : s.shared_passwords.map((p) => (
            <div key={p.logins.join()} className="list-row">
              <Pill tone="warn"><Repeat size={11} /> {p.accounts}</Pill>
              <div className="list-main"><div className="list-sub mono">{p.logins.join(', ')}</div></div>
            </div>
          ))}
          <div className="fineprint">Accounts that leaked with the same password (compared by keyed fingerprint, never in clear).</div>
        </Card>
      </div>
    </>
  );
}
