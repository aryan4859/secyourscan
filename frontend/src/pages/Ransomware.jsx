import React, { useCallback, useState } from 'react';
import { CheckCircle2, ExternalLink, Skull } from 'lucide-react';
import { api } from '../api';
import ScanBar from '../components/ScanBar';
import { Card, Empty, ErrorBox, Pill, Spinner, fmtDate, relTime, useAsync, useToast } from '../components/ui';

export default function Ransomware() {
  const hits = useAsync(() => api.ransomwareHits(), []);
  const [days, setDays] = useState(7);
  const activity = useAsync(() => api.ransomwareActivity(days), [days]);
  const toast = useToast();
  const reload = useCallback(() => { hits.reload(); activity.reload(); }, [hits.reload, activity.reload]);

  const setStatus = async (h, status) => {
    try {
      await api.updateRansomwareHit(h.id, status);
      hits.setData((xs) => xs.map((x) => (x.id === h.id ? { ...x, status } : x)));
    } catch (e) {
      toast(e.message, 'error');
    }
  };

  const open = (hits.data || []).filter((h) => h.status !== 'false_positive');
  const a = activity.data;
  const max = a?.groups[0]?.count || 1;
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Ransomware Watch</h1>
          <p className="muted">Ransomware gangs publish victims on leak sites. Your domains and keywords are searched among those posts via ransomware.live, and any mention raises a critical alert.</p>
        </div>
        <ScanBar module="ransomware" label="Ransomware" onFinished={reload} />
      </div>

      <ErrorBox error={hits.error} onRetry={hits.reload} />
      {hits.loading && !hits.data && <Spinner />}
      {hits.data && open.length === 0 && (
        <div className="rw-clear"><CheckCircle2 size={18} /> <div><b>No leak-site post names your organisation.</b><div className="small muted">Checked against your watched domains and keywords.</div></div></div>
      )}
      {open.map((h) => (
        <div key={h.id} className={`rw-hit ${h.status}`}>
          <div className="rw-icon"><Skull size={20} /></div>
          <div className="rw-main">
            <div className="rw-title">{h.victim} <span className="muted">listed by</span> <b>{h.group}</b></div>
            <div className="list-sub">
              matched “{h.matched}”{h.domain && ` · ${h.domain}`}{h.country && ` · ${h.country}`}{h.activity && ` · ${h.activity}`}
              {' · '}attack {h.attack_date ? fmtDate(h.attack_date) : 'date unknown'} · first seen {relTime(h.first_seen)}
            </div>
            {h.description && h.description !== 'N/A' && <p className="rw-desc">{h.description}</p>}
            <div className="btn-row">
              {h.status === 'new' && <button className="btn btn-sm" onClick={() => setStatus(h, 'acknowledged')}>Acknowledge</button>}
              {h.status === 'acknowledged' && <Pill tone="ok">acknowledged</Pill>}
              <button className="btn btn-sm btn-ghost" onClick={() => setStatus(h, 'false_positive')}>Not us</button>
              {h.url && <a className="btn btn-sm btn-ghost" href={h.url} target="_blank" rel="noreferrer noopener"><ExternalLink size={13} /> ransomware.live</a>}
            </div>
          </div>
        </div>
      ))}

      <div className="dash-row even">
        <Card title="Most active groups" actions={
          <div className="seg">{[7, 14, 30].map((d) => <button key={d} className={d === days ? 'on' : ''} onClick={() => setDays(d)}>{d}d</button>)}</div>
        }>
          <ErrorBox error={activity.error} onRetry={activity.reload} />
          {activity.loading && !a && <Spinner />}
          {a && a.groups.length === 0 && <Empty title="No posts in this window" />}
          {a && a.groups.length > 0 && (
            <ul className="src-bars">
              {a.groups.map((g) => (
                <li key={g.group} title={`${g.group}: ${g.count} posts`} style={{ gridTemplateColumns: 'minmax(80px, 130px) 1fr 40px' }}>
                  <span className="src-name">{g.group}</span>
                  <span className="src-track"><span className="src-fill" style={{ width: `${(g.count / max) * 100}%` }} /></span>
                  <span className="src-num">{g.count}</span>
                </li>
              ))}
            </ul>
          )}
          {a && <div className="fineprint">{a.posts} victims posted in the last {a.days} days · {Object.entries(a.sources || {}).map(([k, v]) => `${k}: ${v}`).join(' · ')}</div>}
        </Card>
        <Card title="Latest leak-site posts">
          {a && a.latest.length === 0 && <Empty title="Nothing recent" />}
          {a?.latest.map((p, i) => (
            <div key={`${p.group}-${p.victim}-${i}`} className="list-row">
              <Pill title={p.source ? `via ${p.source}` : undefined}>{p.group}</Pill>
              <div className="list-main">
                <div className="list-title">{p.victim}</div>
                <div className="list-sub">{[p.country, p.activity].filter((x) => x && x !== 'Not Found').join(' · ') || '—'}</div>
              </div>
              <span className="faint small nowrap">{relTime(p.discovered)}</span>
            </div>
          ))}
          {a?.countries.length > 0 && (
            <div className="tags mt">{a.countries.map((c) => <Pill key={c.country}>{c.country} · {c.count}</Pill>)}</div>
          )}
        </Card>
      </div>
    </div>
  );
}
