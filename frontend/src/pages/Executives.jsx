import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { AtSign, Bug, Crown, Gavel, Globe, Mail, Moon, Pencil, Phone, Plus, Trash2, UserRound } from 'lucide-react';
import { api } from '../api';
import { Card, Drawer, Empty, ErrorBox, Modal, Pill, SeverityBadge, Spinner, StatusPill, TypedConfirm, relTime, useAsync, useToast } from '../components/ui';
import { RiskMeter } from './Identity';
import { Tile } from './Surface';

const split = (s) => s.split(/[\n,]+/).map((x) => x.trim()).filter(Boolean);

export default function Executives() {
  const list = useAsync(() => api.executives(), []);
  const [open, setOpen] = useState(null);
  const [editing, setEditing] = useState(null); // {} = new
  const rows = list.data || [];
  const sum = (k) => rows.reduce((n, x) => n + (x.counts[k] || 0), 0);

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Executive Protection</h1>
          <p className="muted">Your leadership is targeted personally: their mailboxes are phished, their names sold in dox packs, their identity used for CEO fraud. Each profile pulls together leaks that name them, stealer infections of their accounts and domains or handles impersonating them. Their emails and name are watched as VIP items.</p>
        </div>
        <button className="btn btn-primary" onClick={() => setEditing({})}><Plus size={14} /> Add executive</button>
      </div>

      <div className="kpi-grid five">
        <Tile label="Protected people" value={list.data ? rows.length : undefined} sub={`${rows.filter((x) => x.risk >= 60).length} at high risk`} />
        <Tile label="Mentions" value={list.data ? sum('mentions') : undefined} sub={`${sum('open_mentions')} open`} tone={sum('open_mentions') ? 'warn' : ''} />
        <Tile label="On the dark web" value={list.data ? sum('dark_web') : undefined} sub="Tor · Telegram" tone={sum('dark_web') ? 'crit' : ''} />
        <Tile label="Infected accounts" value={list.data ? sum('stealer') : undefined} sub="stealer logs" tone={sum('stealer') ? 'crit' : ''} />
        <Tile label="Impersonation" value={list.data ? sum('impersonation') : undefined} sub="domains · URLs · handles" tone={sum('impersonation') ? 'crit' : ''} />
      </div>

      <ErrorBox error={list.error} onRetry={list.reload} />
      {list.loading && !list.data && <Spinner />}
      {list.data && rows.length === 0 && (
        <div className="card"><Empty title="No executive profiles yet">Add the people attackers would target first: CEO, CFO, finance and IT administrators.</Empty></div>
      )}
      <div className="exec-grid">
        {rows.map((x) => (
          <button key={x.id} className={`exec-card band-${x.band}`} onClick={() => setOpen(x.id)}>
            <div className="exec-top">
              <span className="exec-avatar">{x.name.split(/\s+/).map((p) => p[0]).slice(0, 2).join('').toUpperCase()}</span>
              <div className="exec-who">
                <div className="exec-name">{x.name}</div>
                <div className="sub">{x.title || '—'}</div>
              </div>
              <RiskMeter value={x.risk} />
            </div>
            <div className="exec-stats">
              <span title="Leak mentions"><Moon size={13} /> {x.counts.mentions}</span>
              <span title="Stealer-infected accounts" className={x.counts.stealer ? 'crit' : ''}><Bug size={13} /> {x.counts.stealer}</span>
              <span title="Impersonation" className={x.counts.impersonation ? 'crit' : ''}><Globe size={13} /> {x.counts.impersonation}</span>
              <span className="faint small">{x.last_seen ? `last ${relTime(x.last_seen)}` : 'no mentions'}</span>
            </div>
          </button>
        ))}
      </div>

      {open && <ExecDrawer id={open} onClose={() => setOpen(null)} onEdit={(p) => setEditing(p)} onChanged={list.reload} />}
      {editing && <ExecForm initial={editing} onClose={() => setEditing(null)} onSaved={(p) => { setEditing(null); list.reload(); setOpen(p.id); }} />}
    </div>
  );
}

function ExecDrawer({ id, onClose, onEdit, onChanged }) {
  const p = useAsync(() => api.executive(id), [id]);
  const [confirm, setConfirm] = useState(false);
  const navigate = useNavigate();
  const toast = useToast();
  const x = p.data;

  const takedown = async (imp) => {
    try {
      const td = await api.createTakedown({ source_type: imp.source_type, source_id: imp.source_id, target: imp.target,
        kind: imp.kind, reason: 'impersonation' });
      toast(`${td.ref} drafted`, 'ok');
      navigate(`/takedowns?open=${td.id}`);
    } catch (e) {
      toast(e.message, 'error');
    }
  };

  return (
    <Drawer title={x ? x.name : 'Executive'} onClose={onClose} actions={x && (
      <>
        <button className="btn btn-sm" onClick={() => { onClose(); onEdit(x); }}><Pencil size={13} /> Edit</button>
        <button className="btn btn-sm btn-ghost" onClick={() => setConfirm(true)}><Trash2 size={13} /></button>
      </>
    )}>
      <ErrorBox error={p.error} onRetry={p.reload} />
      {p.loading && !x && <Spinner />}
      {x && (
        <>
          <div className="id-head">
            <RiskMeter value={x.risk} />
            <div className="tags">
              {x.title && <Pill><Crown size={11} /> {x.title}</Pill>}
              {x.emails.map((e) => <Pill key={e}><Mail size={11} /> {e}</Pill>)}
              {x.usernames.map((u) => <Pill key={u}><AtSign size={11} /> {u.replace(/^@/, '')}</Pill>)}
              {x.phones.map((ph) => <Pill key={ph}><Phone size={11} /> {ph}</Pill>)}
            </div>
          </div>

          <Card title={`Impersonation (${x.impersonation.length})`}>
            {x.impersonation.length === 0 ? <Empty title="Nothing impersonating them found" /> : x.impersonation.map((imp) => (
              <div key={`${imp.kind}-${imp.target}`} className="list-row">
                <Pill tone="critical">{imp.kind}</Pill>
                <div className="list-main">
                  <div className="list-title mono">{imp.target}</div>
                  <div className="list-sub">{imp.detail} · risk {imp.risk}</div>
                </div>
                {imp.takedown ? (
                  <button className="btn btn-sm btn-ghost" onClick={() => navigate(`/takedowns?open=${imp.takedown.id}`)}>
                    <StatusPill status={imp.takedown.status} />
                  </button>
                ) : <button className="btn btn-sm" onClick={() => takedown(imp)}><Gavel size={13} /> Takedown</button>}
              </div>
            ))}
          </Card>

          <Card title={`Accounts (${x.accounts.length})`}>
            {x.accounts.length === 0 ? <Empty title="No leaked account" /> : x.accounts.map((a) => (
              <div key={a.login} className="list-row clickable" onClick={() => navigate('/identity?tab=identities&kind=vip')}>
                <RiskMeter value={a.risk} />
                <div className="list-main">
                  <div className="list-title mono">{a.login}</div>
                  <div className="list-sub">
                    {a.stealer ? <Pill tone="critical"><Bug size={11} /> stealer{a.families.length ? ` · ${a.families.join(', ')}` : ''}</Pill> : <Pill>combo list</Pill>}
                    {a.corporate_apps.length > 0 && <span>opens {a.corporate_apps.join(', ')}</span>}
                    {a.reused && <Pill tone="warn">reuse</Pill>}
                  </div>
                </div>
              </div>
            ))}
          </Card>

          <Card title={`Mentions (${x.mentions.length})`}>
            {x.mentions.length === 0 ? <Empty title="Not mentioned in any collected leak" /> : x.mentions.map((m) => (
              <div key={m.leak_id} className="list-row clickable" onClick={() => navigate(`/leaks?id=${m.leak_id}`)}>
                <SeverityBadge value={m.severity} />
                <div className="list-main">
                  <div className="list-title">{m.title}</div>
                  <div className="list-sub"><span>via {m.source}</span>{m.matched.map((h) => <Pill key={h}>{h}</Pill>)}</div>
                </div>
                <span className="faint small nowrap">{relTime(m.at)}</span>
              </div>
            ))}
          </Card>
          {x.notes && <Card title="Notes"><p className="pre-wrap">{x.notes}</p></Card>}
        </>
      )}
      {confirm && x && (
        <TypedConfirm title="Remove executive profile" phrase={x.name} confirmLabel="Remove"
          message="The profile is removed. Their VIP watchlist items stay until you delete them on the Watchlist."
          onConfirm={async () => { await api.deleteExecutive(x.id); onChanged(); onClose(); }} onClose={() => setConfirm(false)} />
      )}
    </Drawer>
  );
}

function ExecForm({ initial, onClose, onSaved }) {
  const isNew = !initial.id;
  const [f, setF] = useState({
    name: initial.name || '', title: initial.title || '', emails: (initial.emails || []).join('\n'),
    usernames: (initial.usernames || []).join('\n'), phones: (initial.phones || []).join('\n'), notes: initial.notes || '',
  });
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value });

  const save = async (e) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    const body = { name: f.name.trim(), title: f.title.trim() || null, emails: split(f.emails), usernames: split(f.usernames),
      phones: split(f.phones), notes: f.notes };
    try {
      onSaved(isNew ? await api.createExecutive(body) : await api.updateExecutive(initial.id, body));
    } catch (e2) {
      setErr(e2);
      setBusy(false);
    }
  };

  return (
    <Modal title={isNew ? 'Add executive' : `Edit ${initial.name}`} onClose={onClose} footer={
      <>
        <button className="btn" onClick={onClose}>Cancel</button>
        <button className="btn btn-primary" form="exec-form" disabled={busy || f.name.trim().length < 3}>{busy ? 'Saving…' : 'Save'}</button>
      </>
    }>
      <form id="exec-form" className="stack-form" onSubmit={save}>
        <label className="field"><span><UserRound size={13} /> Full name</span><input className="input" value={f.name} onChange={set('name')} autoFocus required /></label>
        <label className="field"><span><Crown size={13} /> Title</span><input className="input" value={f.title} onChange={set('title')} placeholder="Chief Financial Officer" /></label>
        <label className="field"><span><Mail size={13} /> Emails (one per line)</span><textarea className="input" rows={2} value={f.emails} onChange={set('emails')} placeholder="jane.doe@yourcompany.com" /></label>
        <label className="field"><span><AtSign size={13} /> Social / chat handles</span><textarea className="input" rows={2} value={f.usernames} onChange={set('usernames')} placeholder="@janedoe" /></label>
        <label className="field"><span><Phone size={13} /> Phone numbers</span><textarea className="input" rows={1} value={f.phones} onChange={set('phones')} /></label>
        <label className="field"><span>Notes</span><textarea className="input" rows={2} value={f.notes} onChange={set('notes')} /></label>
        <p className="fineprint">Emails and the full name are added to the Watchlist as VIP items. Only add people your organisation is responsible for protecting.</p>
        <ErrorBox error={err} />
      </form>
    </Modal>
  );
}
