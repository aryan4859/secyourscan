import React, { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { Eye, ExternalLink, Plus, Save, Swords, Trash2 } from 'lucide-react';
import { api } from '../api';
import { Card, Drawer, Empty, ErrorBox, KV, Modal, Pill, Spinner, useAsync, useToast } from '../components/ui';

const KINDS = [['', 'All'], ['apt', 'State'], ['ransomware', 'Ransomware'], ['cybercrime', 'Cybercrime'], ['hacktivist', 'Hacktivist']];
const KIND_LABEL = { apt: 'state-sponsored', ransomware: 'ransomware', cybercrime: 'cybercrime', hacktivist: 'hacktivist' };
const splitList = (s) => s.split(/[,\n]/).map((x) => x.trim()).filter(Boolean);

export default function ThreatActors() {
  const [tab, setTab] = useState('actors');
  const [kind, setKind] = useState('');
  const [q, setQ] = useState('');
  const list = useAsync(() => api.actors(), []);
  const profile = useAsync(() => api.threatProfile(), []);
  const [openId, setOpenId] = useState(null);
  const [adding, setAdding] = useState(false);

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (list.data || []).filter((a) => (!kind || a.kind === kind)
      && (!needle || [a.name, ...a.aliases, ...a.malware].some((x) => x.toLowerCase().includes(needle))));
  }, [list.data, kind, q]);

  const relevant = (list.data || []).filter((a) => a.relevance >= 25).length;
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Threat Actors</h1>
          <p className="muted">Who is most likely to come after you, and how. Actors are ranked by evidence: naming you or a vendor on a leak site, targeting your sector and country, current leak-site activity, and indicators in your IOC store.</p>
        </div>
        <button className="btn" onClick={() => setAdding(true)}><Plus size={14} /> Add actor</button>
      </div>

      <ProfileCard profile={profile} onSaved={() => list.reload()} />

      <div className="tabs">
        <button className={tab === 'actors' ? 'on' : ''} onClick={() => setTab('actors')}>Actors{list.data ? ` · ${relevant} relevant` : ''}</button>
        <button className={tab === 'attack' ? 'on' : ''} onClick={() => setTab('attack')}>ATT&amp;CK view</button>
      </div>

      {tab === 'actors' && (
        <>
          <div className="form-inline">
            <div className="seg">{KINDS.map(([k, label]) => <button key={k} className={k === kind ? 'on' : ''} onClick={() => setKind(k)}>{label}</button>)}</div>
            <input className="input" style={{ maxWidth: 260 }} placeholder="Name, alias or malware…" value={q} onChange={(e) => setQ(e.target.value)} />
          </div>
          <ErrorBox error={list.error} onRetry={list.reload} />
          {list.loading && !list.data && <Spinner />}
          {list.data && rows.length === 0 && <div className="card"><Empty title="No actor matches" /></div>}
          <div className="actor-grid">
            {rows.map((a) => (
              <button key={a.id} className={`actor-card ${a.observed ? 'observed' : ''}`} onClick={() => setOpenId(a.id)}>
                <div className="actor-head">
                  <span className="actor-name">{a.name}</span>
                  {a.observed && <Pill tone="critical"><Eye size={11} /> observed</Pill>}
                </div>
                <div className="list-sub">{KIND_LABEL[a.kind]}{a.origin && ` · ${a.origin}`}{!a.builtin && ' · custom'}</div>
                <div className="rel-row" title={`Relevance ${a.relevance}/100`}>
                  <span className="rel-track"><span className={`rel-fill ${a.relevance >= 60 ? 'hot' : a.relevance >= 25 ? 'warm' : ''}`} style={{ width: `${a.relevance}%` }} /></span>
                  <span className="rel-num">{a.relevance}</span>
                </div>
                {a.reasons.length > 0
                  ? <ul className="actor-reasons">{a.reasons.slice(0, 3).map((r) => <li key={r}>{r}</li>)}</ul>
                  : <div className="faint small">No link to you yet{a.aliases.length ? ` · aka ${a.aliases.slice(0, 2).join(', ')}` : ''}</div>}
                <div className="faint small">{a.techniques} ATT&amp;CK techniques{a.posts_30d > 0 && ` · ${a.posts_30d} leak-site posts in 30d`}</div>
              </button>
            ))}
          </div>
        </>
      )}

      {tab === 'attack' && <AttackView />}

      {openId && <ActorDrawer id={openId} onClose={() => setOpenId(null)} onDeleted={() => { setOpenId(null); list.reload(); }} />}
      {adding && <AddActor sectors={profile.data?.sector_options || []} onClose={() => setAdding(false)}
        onCreated={(a) => { setAdding(false); list.reload(); setOpenId(a.id); }} />}
    </div>
  );
}

function ProfileCard({ profile, onSaved }) {
  const [sectors, setSectors] = useState([]);
  const [countries, setCountries] = useState('');
  const [busy, setBusy] = useState(false);
  const toast = useToast();
  const p = profile.data;
  useEffect(() => {
    if (p) {
      setSectors(p.sectors);
      setCountries(p.countries.join(', '));
    }
  }, [p]);
  const dirty = p && (sectors.join() !== p.sectors.join() || splitList(countries).map((c) => c.toUpperCase()).join() !== p.countries.join());
  const toggle = (s) => setSectors((cur) => (cur.includes(s) ? cur.filter((x) => x !== s) : [...cur, s].sort()));
  const save = async () => {
    setBusy(true);
    try {
      profile.setData(await api.saveThreatProfile({ sectors, countries: splitList(countries) }));
      toast('Threat profile saved: actors re-ranked', 'ok');
      onSaved();
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      setBusy(false);
    }
  };
  return (
    <Card title="Your threat profile" actions={
      <button className="btn btn-sm btn-primary" disabled={!dirty || busy} onClick={save}><Save size={13} /> Save</button>
    }>
      <ErrorBox error={profile.error} onRetry={profile.reload} />
      {p && (
        <div className="stack">
          <div className="tags">
            {p.sector_options.map((s) => (
              <button key={s} type="button" className={`chip ${sectors.includes(s) ? 'on' : ''}`} onClick={() => toggle(s)}>{s}</button>
            ))}
          </div>
          <label className="field" style={{ maxWidth: 420 }}>
            <span>Countries you operate in (ISO codes, e.g. US, GB, NP)</span>
            <input className="input" value={countries} onChange={(e) => setCountries(e.target.value)} placeholder="US, GB" />
          </label>
          {!p.sectors.length && !p.countries.length && (
            <div className="faint small">Pick your sectors and countries so actors that target organisations like yours rank first.</div>
          )}
        </div>
      )}
    </Card>
  );
}

function AttackView() {
  const m = useAsync(() => api.attackMatrix(), []);
  const [sel, setSel] = useState(null);
  const d = m.data;
  return (
    <>
      <ErrorBox error={m.error} onRetry={m.reload} />
      {m.loading && !d && <Spinner />}
      {d && (
        <>
          <p className="faint small">
            {d.basis === 'relevant'
              ? `Techniques used by the ${d.actors} actor(s) relevant to you. Darker cells are used by more of them; defend those first.`
              : `No actor is linked to you yet, so this shows all ${d.actors} catalogued actors. Set your threat profile to focus it.`}
          </p>
          <div className="attack-matrix">
            {d.columns.map((col) => (
              <div key={col.tactic} className="attack-col">
                <div className="attack-tactic">{col.label}</div>
                {col.techniques.map((t) => (
                  <button key={t.id} className={`attack-cell ${sel?.id === t.id ? 'sel' : ''} ${t.count ? '' : 'none'}`}
                    style={{ '--heat': d.max ? t.count / d.max : 0 }}
                    title={`${t.id} ${t.name}\n${t.count} actor(s): ${t.actors.join(', ') || 'none'}`}
                    onClick={() => setSel(t)}>
                    <span className="mono small">{t.id}</span>
                    <span className="attack-name">{t.name}</span>
                    {t.count > 0 && <span className="attack-count">{t.count}</span>}
                  </button>
                ))}
              </div>
            ))}
          </div>
          {sel && (
            <Card title={`${sel.id} · ${sel.name}`} actions={
              <a className="btn btn-sm btn-ghost" href={`https://attack.mitre.org/techniques/${sel.id.replace('.', '/')}/`} target="_blank" rel="noreferrer noopener">
                <ExternalLink size={13} /> MITRE
              </a>}>
              <KV rows={[['Used by', sel.actors.join(', ') || 'none of these actors'], ['What to do', sel.mitigation]]} />
            </Card>
          )}
          <Card title="Defend first">
            {d.top.length === 0 && <Empty title="No techniques" />}
            {d.top.map((t, i) => (
              <div key={t.id} className="list-row">
                <span className="rank">{i + 1}</span>
                <div className="list-main">
                  <div className="list-title"><span className="mono">{t.id}</span> {t.name}</div>
                  <div className="list-sub">{t.mitigation}</div>
                </div>
                <Pill title={t.actors.join(', ')}>{t.count} actor{t.count === 1 ? '' : 's'}</Pill>
              </div>
            ))}
          </Card>
        </>
      )}
    </>
  );
}

function ActorDrawer({ id, onClose, onDeleted }) {
  const a = useAsync(() => api.actor(id), [id]);
  const toast = useToast();
  const d = a.data;
  const byTactic = useMemo(() => {
    const out = {};
    (d?.techniques_detail || []).forEach((t) => { (out[t.tactic] = out[t.tactic] || []).push(t); });
    return out;
  }, [d]);
  const remove = async () => {
    try {
      await api.deleteActor(id);
      toast(`${d.name} deleted`, 'ok');
      onDeleted();
    } catch (e) {
      toast(e.message, 'error');
    }
  };
  return (
    <Drawer title={d?.name || 'Actor'} onClose={onClose}
      actions={d && !d.builtin && <button className="icon-btn danger" onClick={remove} title="Delete actor"><Trash2 size={16} /></button>}>
      <ErrorBox error={a.error} onRetry={a.reload} />
      {!d && a.loading && <Spinner />}
      {d && (
        <div className="stack">
          <div className="rel-row big">
            <span className="rel-track"><span className={`rel-fill ${d.relevance >= 60 ? 'hot' : d.relevance >= 25 ? 'warm' : ''}`} style={{ width: `${d.relevance}%` }} /></span>
            <span className="rel-num">{d.relevance}/100</span>
          </div>
          {d.reasons.length > 0 && <ul className="actor-reasons">{d.reasons.map((r) => <li key={r}>{r}</li>)}</ul>}
          {d.description && <p className="muted">{d.description}</p>}
          <KV rows={[
            ['Type', KIND_LABEL[d.kind]],
            d.origin && ['Origin', d.origin],
            d.motivation && ['Motivation', d.motivation],
            d.aliases.length > 0 && ['Also known as', d.aliases.join(', ')],
            d.sectors.length > 0 && ['Targets sectors', d.sectors.join(', ')],
            d.countries.length > 0 && ['Targets countries', d.countries.map((c) => c.replace(/^\*/, '').replace('_', ' ')).join(', ')],
            d.malware.length > 0 && ['Malware & tools', d.malware.join(', ')],
          ]} />

          {(d.your_hits.length > 0 || d.your_incidents.length > 0 || d.your_iocs.length > 0) && (
            <Card title="Linked to you">
              {d.your_incidents.map((i) => (
                <div key={i.id} className="list-row"><Pill tone="critical">INC-{String(i.number).padStart(4, '0')}</Pill>
                  <div className="list-main"><Link className="link" to="/incidents">{i.title}</Link></div><span className="faint small">{i.status}</span></div>
              ))}
              {d.your_hits.map((h) => (
                <div key={h.id} className="list-row"><Pill tone="warn">leak site</Pill>
                  <div className="list-main"><Link className="link" to="/ransomware">{h.victim}</Link></div><span className="faint small">{h.status}</span></div>
              ))}
              {d.your_iocs.map((i) => (
                <div key={i.id} className="list-row"><Pill>{i.type}</Pill>
                  <div className="list-main mono-wrap"><Link className="link" to="/iocs">{i.value}</Link></div><span className="faint small">{i.verdict}</span></div>
              ))}
            </Card>
          )}

          <h4 className="section-title">Techniques (MITRE ATT&amp;CK)</h4>
          {Object.entries(byTactic).map(([tac, ts]) => (
            <div key={tac}>
              <div className="faint small tactic-label">{tac.replace(/-/g, ' ')}</div>
              {ts.map((t) => (
                <div key={t.id} className="list-row">
                  <a className="link mono" href={`https://attack.mitre.org/techniques/${t.id.replace('.', '/')}/`} target="_blank" rel="noreferrer noopener">{t.id}</a>
                  <div className="list-main"><div>{t.name}</div>{t.mitigation && <div className="list-sub">{t.mitigation}</div>}</div>
                </div>
              ))}
            </div>
          ))}
          {d.references.length > 0 && (
            <div className="btn-row">
              {d.references.map((r) => <a key={r} className="btn btn-sm btn-ghost" href={r} target="_blank" rel="noreferrer noopener"><ExternalLink size={13} /> {new URL(r).hostname}</a>)}
            </div>
          )}
        </div>
      )}
    </Drawer>
  );
}

function AddActor({ sectors, onClose, onCreated }) {
  const [f, setF] = useState({ name: '', aliases: '', kind: 'cybercrime', origin: '', motivation: '', description: '',
    sectors: [], countries: '', techniques: '', malware: '' });
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);
  const set = (k) => (e) => setF((x) => ({ ...x, [k]: e.target.value }));
  const submit = async () => {
    setBusy(true);
    setErr(null);
    try {
      onCreated(await api.createActor({
        ...f, aliases: splitList(f.aliases), countries: splitList(f.countries).map((c) => c.toUpperCase()),
        techniques: splitList(f.techniques).map((t) => t.toUpperCase()), malware: splitList(f.malware),
        origin: f.origin || null, motivation: f.motivation || null,
      }));
    } catch (e) {
      setErr(e);
      setBusy(false);
    }
  };
  return (
    <Modal title="Add a threat actor" wide onClose={onClose} footer={
      <>
        <button className="btn" onClick={onClose}>Cancel</button>
        <button className="btn btn-primary" disabled={busy || f.name.trim().length < 2} onClick={submit}><Swords size={14} /> Add actor</button>
      </>
    }>
      <div className="stack">
        <div className="form-inline">
          <label className="field grow"><span>Name <span className="req">*</span></span><input className="input" autoFocus value={f.name} onChange={set('name')} /></label>
          <label className="field"><span>Type</span>
            <select className="input" value={f.kind} onChange={set('kind')}>{KINDS.slice(1).map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select>
          </label>
        </div>
        <label className="field"><span>Aliases (comma-separated; include leak-site group names)</span><input className="input" value={f.aliases} onChange={set('aliases')} /></label>
        <div className="form-inline">
          <label className="field grow"><span>Origin</span><input className="input" value={f.origin} onChange={set('origin')} /></label>
          <label className="field grow"><span>Motivation</span><input className="input" value={f.motivation} onChange={set('motivation')} /></label>
        </div>
        <div className="field"><span>Targets sectors</span>
          <div className="tags">{sectors.map((s) => (
            <button key={s} type="button" className={`chip ${f.sectors.includes(s) ? 'on' : ''}`}
              onClick={() => setF((x) => ({ ...x, sectors: x.sectors.includes(s) ? x.sectors.filter((y) => y !== s) : [...x.sectors, s] }))}>{s}</button>
          ))}</div>
        </div>
        <label className="field"><span>Targets countries (ISO codes)</span><input className="input" value={f.countries} onChange={set('countries')} placeholder="US, GB" /></label>
        <label className="field"><span>ATT&amp;CK technique ids</span><input className="input mono" value={f.techniques} onChange={set('techniques')} placeholder="T1566.001, T1486" /></label>
        <label className="field"><span>Malware &amp; tools</span><input className="input" value={f.malware} onChange={set('malware')} /></label>
        <label className="field"><span>Description</span><textarea className="input" rows={3} value={f.description} onChange={set('description')} /></label>
        <ErrorBox error={err} />
      </div>
    </Modal>
  );
}
