import React, { useState } from 'react';
import { BadgeCheck, Clock, Plus, RefreshCw, Trash2 } from 'lucide-react';
import { api } from '../api';
import { Card, CopyButton, Empty, ErrorBox, Pill, Spinner, TypedConfirm, fmtDate, relTime, useAsync, useToast } from '../components/ui';

export default function Domains() {
  const list = useAsync(() => api.domains(), []);
  const [domain, setDomain] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  const [checking, setChecking] = useState(null);
  const [removing, setRemoving] = useState(null);
  const toast = useToast();
  const items = list.data?.items || [];

  const add = async (e) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      const d = await api.addDomain(domain.trim());
      list.setData((x) => ({ ...x, items: [...(x?.items || []), d] }));
      setDomain('');
    } catch (e2) {
      setErr(e2);
    } finally {
      setBusy(false);
    }
  };

  const verify = async (d) => {
    setChecking(d.id);
    try {
      const v = await api.verifyDomain(d.id);
      list.setData((x) => ({ ...x, items: x.items.map((y) => (y.id === d.id ? v : y)) }));
      toast(v.verified ? `${v.domain} verified` : `${v.domain}: ${v.last_error}`, v.verified ? 'ok' : 'error');
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      setChecking(null);
    }
  };

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Domains</h1>
          <p className="muted">Prove you control a root domain before SecYourScan monitors it. Verification covers the domain and all of its subdomains.</p>
        </div>
        {list.data && (
          <Pill tone={list.data.required ? 'ok' : 'warn'}>
            {list.data.required ? 'Verification required for scans' : 'Verification not enforced (REQUIRE_DOMAIN_VERIFICATION=false)'}
          </Pill>
        )}
      </div>

      <Card title="Add a domain">
        <form className="form-inline" onSubmit={add}>
          <label className="field grow">
            <span>Root domain</span>
            <input className="input" placeholder="example.com" value={domain} onChange={(e) => setDomain(e.target.value)} />
          </label>
          <button className="btn btn-primary" disabled={busy || domain.trim().length < 3}><Plus size={14} /> Add</button>
        </form>
        <ErrorBox error={err} />
      </Card>

      <ErrorBox error={list.error} onRetry={list.reload} />
      {list.loading && !list.data && <Spinner />}
      {list.data && items.length === 0 && <div className="card"><Empty title="No domains yet">Add the root domains your organisation owns.</Empty></div>}

      {items.map((d) => (
        <section key={d.id} className={`card domain-card ${d.verified ? 'is-verified' : ''}`}>
          <header className="card-head">
            <h2>{d.verified ? <BadgeCheck size={16} className="ok-icon" /> : <Clock size={16} className="warn-icon" />} {d.domain}</h2>
            <div className="card-actions">
              {d.verified ? <Pill tone="ok">verified {relTime(d.verified_at)}</Pill> : <Pill tone="warn">pending</Pill>}
              <button className="btn btn-sm" onClick={() => verify(d)} disabled={checking === d.id}>
                <RefreshCw size={13} className={checking === d.id ? 'spin' : ''} /> {d.verified ? 'Re-check' : 'Verify now'}
              </button>
              <button className="icon-btn danger" onClick={() => setRemoving(d)} aria-label={`Remove ${d.domain}`}><Trash2 size={15} /></button>
            </div>
          </header>
          <div className="card-body">
            {!d.verified && <p className="small muted">Add this TXT record at your DNS provider, wait for it to propagate (usually minutes), then press <b>Verify now</b>.</p>}
            <div className="dns-instr">
              <div><span className="faint small">Type</span><code>TXT</code></div>
              <div><span className="faint small">Name / host</span><code>{d.record_name}</code><CopyButton text={d.record_name} label="" /></div>
              <div><span className="faint small">Value</span><code>{d.record_value}</code><CopyButton text={d.record_value} label="" /></div>
            </div>
            {d.last_error && !d.verified && <p className="small error-text mt">Last check {relTime(d.last_checked_at)}: {d.last_error}</p>}
            {d.verified && <p className="small muted mt">Keep the record in place; it is re-checked on demand. Added {fmtDate(d.created_at)}.</p>}
          </div>
        </section>
      ))}

      {removing && (
        <TypedConfirm title="Remove domain" phrase={removing.domain}
          message="Scans will stop covering this domain and its subdomains when verification is required."
          confirmLabel="Remove" onClose={() => setRemoving(null)}
          onConfirm={async () => {
            await api.deleteDomain(removing.id);
            list.setData((x) => ({ ...x, items: x.items.filter((y) => y.id !== removing.id) }));
          }} />
      )}
    </div>
  );
}
