import React, { useState } from 'react';
import { AlertTriangle, Check, Download, ExternalLink } from 'lucide-react';
import { api } from '../api';
import {
  Drawer, Empty, ErrorBox, JsonView, KV, Pill, SeverityBadge, Spinner, StatusPill, fmtDate, statusLabel, useAsync, useToast,
} from './ui';

const ACTIONS = ['reviewing', 'escalated', 'resolved', 'false_positive'];

export default function LeakDrawer({ id, onClose, onChanged }) {
  const leak = useAsync(() => api.leak(id), [id]);
  const toast = useToast();
  const [busy, setBusy] = useState(null);
  const [confirmEvidence, setConfirmEvidence] = useState(false);

  const apply = (summary) => {
    leak.setData((d) => ({ ...d, ...summary, snippet: d.snippet }));
    onChanged?.(summary);
  };

  const setStatus = async (status) => {
    setBusy(status);
    try {
      apply(await api.setLeakStatus(id, status));
      toast(`Marked ${statusLabel(status)}`, 'ok');
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      setBusy(null);
    }
  };
  const ack = async () => {
    setBusy('ack');
    try {
      apply(await api.ackLeak(id));
      toast('Acknowledged', 'ok');
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      setBusy(null);
    }
  };
  const evidence = async () => {
    setBusy('evidence');
    try {
      await api.downloadEvidence(id);
      setConfirmEvidence(false);
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      setBusy(null);
    }
  };

  const l = leak.data;
  const sightings = l?.metadata?.sightings || [];
  const metadata = l ? Object.fromEntries(Object.entries(l.metadata || {}).filter(([k]) => k !== 'sightings')) : {};

  return (
    <Drawer title={l ? l.title || 'Leak detail' : 'Leak detail'} onClose={onClose}>
      <ErrorBox error={leak.error} onRetry={leak.reload} />
      {leak.loading && !l && <Spinner />}
      {l && (
        <>
          <div className="detail-top">
            <SeverityBadge value={l.severity} />
            <StatusPill status={l.status} />
            {l.category && <Pill>{l.category}</Pill>}
            {l.acknowledged_at ? <Pill tone="ok">acked {fmtDate(l.acknowledged_at)}</Pill> : <Pill tone="critical">unacknowledged</Pill>}
          </div>

          <div className="btn-row wrap">
            {ACTIONS.map((s) => (
              <button key={s} className={`btn btn-sm ${l.status === s ? 'btn-on' : ''} act-${s}`} disabled={!!busy || l.status === s}
                onClick={() => setStatus(s)}>
                {busy === s ? '…' : statusLabel(s)}
              </button>
            ))}
            <button className="btn btn-sm" disabled={!!busy || !!l.acknowledged_at} onClick={ack}>
              <Check size={13} /> {l.acknowledged_at ? 'Acknowledged' : 'Acknowledge'}
            </button>
            {l.has_evidence && (
              <button className="btn btn-sm btn-warn" disabled={!!busy} onClick={() => setConfirmEvidence(true)}>
                <Download size={13} /> Download raw evidence
              </button>
            )}
          </div>

          {confirmEvidence && (
            <div className="warn-box">
              <AlertTriangle size={16} />
              <div>
                <b>Raw evidence is unmasked.</b> It can contain live passwords, tokens and personal data exactly as found.
                Handle it under your incident procedure; the download is recorded in the audit log.
                <div className="btn-row">
                  <button className="btn btn-sm btn-warn" onClick={evidence} disabled={busy === 'evidence'}>
                    {busy === 'evidence' ? 'Downloading…' : 'I understand, download'}
                  </button>
                  <button className="btn btn-sm" onClick={() => setConfirmEvidence(false)}>Cancel</button>
                </div>
              </div>
            </div>
          )}

          <Section title="Masked snippet">
            <pre className="snippet-block">{l.snippet || '(empty)'}</pre>
          </Section>

          <Section title="Matched watch items">
            {l.watch_matches?.length ? (
              <div className="tags">
                {l.watch_matches.map((m) => (
                  <Pill key={m.id || m.value} tone={m.vip ? 'vip' : 'default'} title={m.hits ? `hit on: ${JSON.stringify(m.hits)}` : m.type}>
                    {m.vip && '★ '}{m.type}: {m.value}
                  </Pill>
                ))}
              </div>
            ) : <span className="muted">None</span>}
          </Section>

          <Section title="Overview">
            <KV rows={[
              ['Source', l.source],
              ['Source URL', l.source_url ? (
                <span className="mono-wrap">{l.source_url}{/^https?:\/\//i.test(l.source_url) && (
                  <a className="link ext" href={l.source_url} target="_blank" rel="noopener noreferrer nofollow" title="Opens the original location">
                    <ExternalLink size={12} />
                  </a>
                )}</span>
              ) : null],
              ['SHA-256', <code className="mono-wrap" key="sha">{l.sha256}</code>],
              ['Discovered', fmtDate(l.discovered_at)],
              ['Last seen', fmtDate(l.last_seen_at)],
              ['Seen count', l.seen_count],
              ['Emails', l.email_count],
              ['Credentials', l.credential_count],
              ['ID', <code key="id">{l.id}</code>],
            ]} />
          </Section>

          <Section title="Entities"><Entities entities={l.entities} /></Section>

          <Section title={`YARA matches (${l.yara_matches?.length || 0})`}>
            {l.yara_matches?.length ? (
              <ul className="plain-list">
                {l.yara_matches.map((m, i) => (
                  <li key={i}>
                    <Pill tone="rule">{m.rule}</Pill>
                    {m.score != null && <Pill tone="warn">+{m.score}</Pill>}
                    {m.category && <Pill>{m.category}</Pill>}
                    {m.description && <span className="muted"> {m.description}</span>}
                    <JsonView title="details" data={m} />
                  </li>
                ))}
              </ul>
            ) : <span className="muted">No rules matched</span>}
          </Section>

          <Section title="AI analysis">
            {l.ai_analysis ? (
              <>
                <KV rows={[
                  ['Valid finding', l.ai_analysis.is_valid == null ? null : l.ai_analysis.is_valid ? 'yes' : 'no'],
                  ['AI severity', l.ai_analysis.severity],
                  ['AI category', l.ai_analysis.category],
                  ['Rationale', l.ai_analysis.rationale],
                ]} />
                <p className="fineprint">Model output derived from untrusted material. Treat as a hint, not a verdict.</p>
                <JsonView title="raw analysis" data={l.ai_analysis} />
              </>
            ) : <span className="muted">Not analysed (AI disabled or unavailable at ingest time)</span>}
          </Section>

          <Section title="Threat intel (CTI)">
            {l.cti && Object.keys(l.cti).length ? <JsonView data={l.cti} /> : <span className="muted">No enrichment</span>}
          </Section>

          <Section title={`Sightings (${sightings.length})`}>
            {sightings.length ? (
              <div className="table-wrap">
                <table className="table compact">
                  <thead><tr><th>When</th><th>Source</th><th>URL</th></tr></thead>
                  <tbody>
                    {sightings.map((s, i) => (
                      <tr key={i}><td className="nowrap">{fmtDate(s.at)}</td><td>{s.source}</td><td className="mono-wrap">{s.url || '—'}</td></tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : <span className="muted">Only the first sighting is recorded so far</span>}
          </Section>

          <Section title="Metadata">
            {Object.keys(metadata).length ? <JsonView data={metadata} /> : <span className="muted">None</span>}
          </Section>
        </>
      )}
      {!leak.loading && !l && !leak.error && <Empty title="Leak not found" />}
    </Drawer>
  );
}

function Section({ title, children }) {
  return (
    <section className="detail-section">
      <h4>{title}</h4>
      {children}
    </section>
  );
}

function Entities({ entities }) {
  const entries = Object.entries(entities || {});
  if (!entries.length) return <span className="muted">None extracted</span>;
  return (
    <div className="entities">
      {entries.map(([k, v]) => (
        <div key={k} className="entity-group">
          <div className="entity-key">{k.replace(/_/g, ' ')}{Array.isArray(v) && ` (${v.length})`}</div>
          {Array.isArray(v) ? (
            <div className="tags">
              {v.slice(0, 50).map((x, i) => (
                <Pill key={i}>{typeof x === 'string' || typeof x === 'number' ? x
                  : x && x.identifier ? `${x.identifier} : ${x.password_masked ?? '***'}${x.password_length ? ` (${x.password_length} chars)` : ''}`
                    : JSON.stringify(x)}</Pill>
              ))}
              {v.length > 50 && <span className="muted">+{v.length - 50} more</span>}
            </div>
          ) : typeof v === 'object' && v !== null ? <JsonView data={v} /> : <span>{String(v)}</span>}
        </div>
      ))}
    </div>
  );
}
