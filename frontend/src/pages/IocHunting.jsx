import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Crosshair, Download, RefreshCw, Share2, Trash2 } from 'lucide-react';
import { api } from '../api';
import {
  Card, CopyButton, Drawer, Empty, ErrorBox, JsonView, KV, Modal, Pill, Spinner, Toggle, fmtDate, relTime, useAsync, useToast,
} from '../components/ui';
import useDebounced from '../useDebounced';
import { Tile } from './Surface';

const VERDICT_TONE = { malicious: 'critical', suspicious: 'warn', clean: 'ok', unknown: 'default' };
const VERDICTS = ['malicious', 'suspicious', 'unknown', 'clean'];
const TYPES = ['ip', 'domain', 'url', 'md5', 'sha1', 'sha256', 'email'];
const TLPS = ['clear', 'green', 'amber', 'red'];
const SIGHTING_PAGE = { surface: '/surface', vendor: '/supply-chain', lookalike: '/brand', phishing: '/brand', watch: '/watchlist', leak: '/leaks' };
const COLLECTION_ID = 'b3c1f2e4-7a1d-4f6b-9a0e-5c2d8e7f1a90';

export function Verdict({ v, score }) {
  return <Pill tone={VERDICT_TONE[v]} title={score != null ? `score ${score}` : undefined}>{v}{score ? ` · ${score}` : ''}</Pill>;
}

export default function IocHunting() {
  const [verdict, setVerdict] = useState('');
  const [type, setType] = useState('');
  const [sighted, setSighted] = useState(false);
  const [q, setQ] = useState('');
  const dq = useDebounced(q.trim(), 300);
  const store = useAsync(() => api.iocs({ verdict, type, q: dq, sighted: sighted || undefined }), [verdict, type, dq, sighted]);
  const stats = useAsync(() => api.iocStats(), []);
  const [openId, setOpenId] = useState(null);
  const [lastHunt, setLastHunt] = useState(null);
  const [sharing, setSharing] = useState(false);

  const refresh = () => { store.reload(); stats.reload(); };
  const s = stats.data;
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>IOC Hunting</h1>
          <p className="muted">Paste IPs, domains, URLs, hashes or emails (defanged is fine). Each is checked against threat-intel sources and retro-hunted across your own data: attack surface, watchlist, vendors, leaks, lookalikes. Results are kept, re-checked weekly and can be shared with your SIEM.</p>
        </div>
        <button className="btn" onClick={() => setSharing(true)}><Share2 size={14} /> Export &amp; TAXII</button>
      </div>

      <HuntBox onDone={(r) => { setLastHunt(r); refresh(); }} />

      {lastHunt && (
        <Card title={`Hunt results · ${lastHunt.results.length} indicator(s)`} actions={
          <button className="btn btn-sm btn-ghost" onClick={() => setLastHunt(null)}>Clear</button>
        }>
          {lastHunt.truncated && <div className="warn-text small">Only the first 100 indicators were checked.</div>}
          {lastHunt.rejected.length > 0 && <div className="faint small">Not recognised: {lastHunt.rejected.join(', ')}</div>}
          {lastHunt.incidents_opened > 0 && (
            <div className="error-text small"><Link className="link" to="/incidents">{lastHunt.incidents_opened} incident(s) opened</Link>: malicious indicators seen on your assets.</div>
          )}
          <IocTable rows={lastHunt.results} onOpen={setOpenId} showNew />
        </Card>
      )}

      <div className="kpi-grid">
        <Tile label="Indicators" value={s?.total} sub={s ? Object.entries(s.by_type).map(([k, v]) => `${v} ${k}`).join(' · ') || 'none yet' : ''} />
        <Tile label="Malicious" value={s?.by_verdict.malicious} sub="score ≥ 75" tone={s?.by_verdict.malicious ? 'crit' : ''} onClick={() => setVerdict('malicious')} />
        <Tile label="Suspicious" value={s?.by_verdict.suspicious} sub="score 40–74" tone={s?.by_verdict.suspicious ? 'warn' : ''} onClick={() => setVerdict('suspicious')} />
        <Tile label="Malicious on your assets" value={s?.sighted_malicious} sub="each one opens an incident" tone={s?.sighted_malicious ? 'crit' : ''}
          onClick={() => { setVerdict('malicious'); setSighted(true); }} />
      </div>

      <Card title="Indicator store">
        <div className="form-inline">
          <div className="seg">
            {['', ...VERDICTS].map((v) => <button key={v} className={v === verdict ? 'on' : ''} onClick={() => setVerdict(v)}>{v || 'all'}</button>)}
          </div>
          <select className="input" value={type} onChange={(e) => setType(e.target.value)} aria-label="Type">
            <option value="">Any type</option>
            {TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
          <input className="input" style={{ maxWidth: 240 }} placeholder="Search value or note…" value={q} onChange={(e) => setQ(e.target.value)} />
          <Toggle checked={sighted} onChange={setSighted} label="Seen in my data" />
        </div>
        <ErrorBox error={store.error} onRetry={store.reload} />
        {store.loading && !store.data && <Spinner />}
        {store.data && store.data.length === 0 && <Empty title="No indicators">Hunt something above to start the store.</Empty>}
        {store.data?.length > 0 && <IocTable rows={store.data} onOpen={setOpenId} />}
      </Card>

      {openId && <IocDrawer id={openId} onClose={() => setOpenId(null)} onChanged={refresh} onDeleted={() => { setOpenId(null); refresh(); }} />}
      {sharing && <ShareModal onClose={() => setSharing(false)} />}
    </div>
  );
}

function HuntBox({ onDone }) {
  const [text, setText] = useState('');
  const [tags, setTags] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  const sources = useAsync(() => api.iocSources(), []);
  const toast = useToast();
  const count = text.split(/[\s,;]+/).filter(Boolean).length;
  const hunt = async (e) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      const r = await api.huntIocs(text, tags.split(',').map((t) => t.trim()).filter(Boolean));
      const bad = r.results.filter((x) => x.verdict === 'malicious').length;
      toast(`${r.results.length} checked · ${bad} malicious`, bad ? 'error' : 'ok');
      onDone(r);
    } catch (e2) {
      setErr(e2);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Card title="Hunt">
      <form className="stack" onSubmit={hunt}>
        <textarea className="input code" rows={5} value={text} onChange={(e) => setText(e.target.value)}
          placeholder={'185.220.101[.]4\nhxxps://login-microsoft-verify[.]top/auth\n44d88612fea8a8f36de82e1278abb02f'} />
        <div className="form-inline">
          <input className="input" style={{ maxWidth: 260 }} value={tags} onChange={(e) => setTags(e.target.value)} placeholder="Tags, e.g. case-42, phishing" />
          <button className="btn btn-primary" disabled={busy || !text.trim()}>
            {busy ? <RefreshCw size={14} className="spin" /> : <Crosshair size={14} />} {busy ? 'Hunting…' : `Hunt${count ? ` ${Math.min(count, 100)}` : ''}`}
          </button>
          {sources.data && (
            <div className="tags">
              {Object.entries(sources.data).map(([k, on]) => (
                <Pill key={k} tone={on ? 'ok' : 'default'} title={on ? 'configured' : 'add its API key to enable'}>{k}</Pill>
              ))}
            </div>
          )}
        </div>
        <ErrorBox error={err} />
      </form>
    </Card>
  );
}

function IocTable({ rows, onOpen, showNew = false }) {
  return (
    <div className="table-wrap">
      <table className="table">
        <thead><tr><th>Verdict</th><th>Indicator</th><th>Malware · actor</th><th>Seen in your data</th><th>Sources</th><th>Checked</th></tr></thead>
        <tbody>
          {rows.map((i) => (
            <tr key={i.id} className="clickable" onClick={() => onOpen(i.id)}>
              <td><Verdict v={i.verdict} score={i.score} /></td>
              <td>
                <div className="mono-wrap">{i.value}</div>
                <div className="sub">{i.type}{i.tags.length > 0 && ` · ${i.tags.join(', ')}`}{showNew && i.new && ' · new'}{i.verdict_override && ' · analyst verdict'}</div>
              </td>
              <td>
                <div className="tags">
                  {i.malware.slice(0, 3).map((m) => <Pill key={m} tone="critical">{m}</Pill>)}
                  {i.actors.map((a) => <Pill key={a} tone="vip">{a}</Pill>)}
                  {!i.malware.length && !i.actors.length && <span className="faint">—</span>}
                </div>
              </td>
              <td>{i.asset_sightings ? <Pill tone="critical">{i.asset_sightings} asset{i.asset_sightings === 1 ? '' : 's'}</Pill>
                : i.sightings ? <Pill tone="warn">{i.sightings} mention{i.sightings === 1 ? '' : 's'}</Pill> : <span className="faint">no</span>}</td>
              <td className="small">{Object.entries(i.sources).filter(([k]) => k !== '_note').length || <span className="faint">{i.sources._note ? 'private' : '—'}</span>}</td>
              <td className="faint small nowrap">{relTime(i.last_enriched_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function IocDrawer({ id, onClose, onChanged, onDeleted }) {
  const r = useAsync(() => api.ioc(id), [id]);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState('');
  const [tags, setTags] = useState('');
  const toast = useToast();
  const d = r.data;
  useEffect(() => {
    if (d) {
      setNote(d.note || '');
      setTags(d.tags.join(', '));
    }
  }, [d?.id]); // eslint-disable-line react-hooks/exhaustive-deps

  const run = async (fn, msg) => {
    setBusy(true);
    try {
      r.setData(await fn());
      if (msg) toast(msg, 'ok');
      onChanged();
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      setBusy(false);
    }
  };
  const remove = async () => {
    try {
      await api.deleteIoc(id);
      onDeleted();
    } catch (e) {
      toast(e.message, 'error');
    }
  };
  return (
    <Drawer title={d ? d.value : 'Indicator'} onClose={onClose} actions={d && (
      <>
        <button className="icon-btn" disabled={busy} onClick={() => run(() => api.enrichIoc(id), 'Re-checked')} title="Re-check now"><RefreshCw size={16} className={busy ? 'spin' : ''} /></button>
        <button className="icon-btn danger" onClick={remove} title="Delete"><Trash2 size={16} /></button>
      </>
    )}>
      <ErrorBox error={r.error} onRetry={r.reload} />
      {!d && r.loading && <Spinner />}
      {d && (
        <div className="stack">
          <div className="form-inline">
            <Verdict v={d.verdict} score={d.score} />
            <label className="field"><span>Analyst verdict</span>
              <select className="input" value={d.verdict_override ? d.verdict : ''} disabled={busy}
                onChange={(e) => run(() => api.updateIoc(id, e.target.value ? { verdict: e.target.value } : { clear_override: true }))}>
                <option value="">automatic</option>
                {VERDICTS.map((v) => <option key={v} value={v}>{v}</option>)}
              </select>
            </label>
            <label className="field"><span>TLP</span>
              <select className="input" value={d.tlp} disabled={busy} onChange={(e) => run(() => api.updateIoc(id, { tlp: e.target.value }))}>
                {TLPS.map((t) => <option key={t} value={t}>TLP:{t.toUpperCase()}</option>)}
              </select>
            </label>
          </div>
          <KV rows={[
            ['Type', d.type],
            d.malware.length > 0 && ['Malware', d.malware.join(', ')],
            d.actors.length > 0 && ['Threat actors', <Link key="a" className="link" to="/actors">{d.actors.join(', ')}</Link>],
            ['First added', `${fmtDate(d.first_seen)}${d.created_by ? ` by ${d.created_by}` : ''}`],
            ['Last checked', fmtDate(d.last_enriched_at)],
          ]} />

          <h4 className="section-title">Seen in your data</h4>
          {d.sightings_detail.length === 0 && <div className="faint small">Not found in your attack surface, watchlist, vendors, leaks, lookalikes or phishing records.</div>}
          {d.sightings_detail.map((sg, i) => {
            const page = SIGHTING_PAGE[(sg.ref || '').split(':')[0]];
            return (
              <div key={i} className="list-row">
                <Pill tone={sg.kind === 'asset' ? 'critical' : 'warn'}>{sg.kind}</Pill>
                <div className="list-main">{page ? <Link className="link" to={page}>{sg.where}</Link> : sg.where}</div>
              </div>
            );
          })}

          <h4 className="section-title">Sources</h4>
          {Object.entries(d.enrichment).map(([src, res]) => (
            <div key={src} className="src-result">
              <div className="list-row">
                <b className="small">{src === '_note' ? 'note' : src}</b>
                <div className="list-main small">{res.error ? <span className="error-text">{res.error}</span> : res.summary}</div>
                {res.score > 0 && <Pill tone={res.score >= 75 ? 'critical' : res.score >= 40 ? 'warn' : 'default'}>{res.score}</Pill>}
              </div>
              {!res.error && src !== '_note' && <JsonView data={res} title="details" />}
            </div>
          ))}

          <label className="field"><span>Tags</span>
            <input className="input" value={tags} onChange={(e) => setTags(e.target.value)}
              onBlur={() => tags !== d.tags.join(', ') && run(() => api.updateIoc(id, { tags: tags.split(',').map((t) => t.trim()).filter(Boolean) }))} />
          </label>
          <label className="field"><span>Analyst note</span>
            <textarea className="input" rows={3} value={note} onChange={(e) => setNote(e.target.value)}
              onBlur={() => note !== (d.note || '') && run(() => api.updateIoc(id, { note }), 'Note saved')} />
          </label>
        </div>
      )}
    </Drawer>
  );
}

function ShareModal({ onClose }) {
  const [minVerdict, setMinVerdict] = useState('suspicious');
  const [maxTlp, setMaxTlp] = useState('amber');
  const [blType, setBlType] = useState('ip');
  const toast = useToast();
  const taxii = `${window.location.origin}/taxii2/`;
  const dl = (fn) => fn().catch((e) => toast(e.message, 'error'));
  return (
    <Modal title="Share indicators" wide onClose={onClose}>
      <div className="stack">
        <h4 className="section-title">STIX 2.1 bundle</h4>
        <div className="form-inline">
          <label className="field"><span>Include</span>
            <select className="input" value={minVerdict} onChange={(e) => setMinVerdict(e.target.value)}>
              <option value="malicious">malicious only</option>
              <option value="suspicious">malicious + suspicious</option>
              <option value="any">everything</option>
            </select>
          </label>
          <label className="field"><span>Up to</span>
            <select className="input" value={maxTlp} onChange={(e) => setMaxTlp(e.target.value)}>
              {TLPS.map((t) => <option key={t} value={t}>TLP:{t.toUpperCase()}</option>)}
            </select>
          </label>
          <button className="btn btn-primary" onClick={() => dl(() => api.exportStix({ min_verdict: minVerdict, max_tlp: maxTlp }))}><Download size={14} /> Download STIX</button>
        </div>

        <h4 className="section-title">Blocklist</h4>
        <div className="form-inline">
          <select className="input" value={blType} onChange={(e) => setBlType(e.target.value)}>
            {TYPES.filter((t) => t !== 'email').map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
          <button className="btn" onClick={() => dl(() => api.exportBlocklist(blType))}><Download size={14} /> Download .txt</button>
          <span className="faint small">Malicious indicators, one per line, for firewalls, proxies and DNS filters.</span>
        </div>

        <h4 className="section-title">TAXII 2.1 feed</h4>
        <p className="faint small">Point your SIEM or threat-intel platform's TAXII 2.1 client here. Authenticate with an API key that has the <code>read</code> scope (Settings → API keys), sent as <code>Authorization: Bearer sys_…</code>. Serves malicious and suspicious indicators up to TLP:AMBER.</p>
        <KV rows={[
          ['Discovery', <span key="d" className="btn-row"><code>{taxii}</code><CopyButton text={taxii} /></span>],
          ['Collection id', <span key="c" className="btn-row"><code>{COLLECTION_ID}</code><CopyButton text={COLLECTION_ID} /></span>],
        ]} />
      </div>
    </Modal>
  );
}
