import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Play, Plus, RefreshCw, Trash2 } from 'lucide-react';
import { api } from '../api';
import {
  Card, Empty, ErrorBox, JsonView, KV, Modal, Pill, Spinner, Toggle, fmtDate, relTime, useAsync, useToast,
} from '../components/ui';

const KINDS = ['ahmia', 'onion', 'telegram', 'feed', 'github', 'hibp'];
const NEEDS_TARGET = new Set(['onion', 'telegram', 'feed']);
const TARGET_HINT = {
  ahmia: 'optional search term (defaults to your watchlist)',
  onion: 'http://…onion/ (required)',
  telegram: 'public channel name (required)',
  feed: 'https://… RSS/Atom URL (required)',
  github: 'optional search term (defaults to your watchlist)',
  hibp: 'optional (uses your watched domains/emails)',
};

export default function Sources() {
  const sources = useAsync(() => api.sources(), []);
  const runs = useAsync(() => api.runs({ limit: 50 }), []);
  const toast = useToast();
  const [runId, setRunId] = useState(null);

  // Poll while something is still running.
  const anyRunning = runs.data?.some((r) => r.status === 'running');
  useEffect(() => {
    if (!anyRunning) return undefined;
    const t = setInterval(runs.reload, 5000);
    return () => clearInterval(t);
  }, [anyRunning, runs.reload]);

  const runNow = async (s) => {
    try {
      const r = await api.runSource(s.id);
      toast(`Run queued for ${s.kind}${s.target ? ` ${s.target}` : ''} (${r.mode})`, 'ok');
      setTimeout(runs.reload, 800);
    } catch (e) {
      toast(e.message, 'error');
    }
  };
  const update = async (s, patch) => {
    try {
      const u = await api.updateSource(s.id, patch);
      sources.setData((xs) => xs.map((x) => (x.id === s.id ? u : x)));
    } catch (e) {
      toast(e.message, 'error');
    }
  };
  const remove = async (s) => {
    if (!window.confirm(`Delete the ${s.kind} source${s.target ? ` "${s.target}"` : ''}?`)) return;
    try {
      await api.deleteSource(s.id);
      sources.setData((xs) => xs.filter((x) => x.id !== s.id));
    } catch (e) {
      toast(e.message, 'error');
    }
  };

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Sources</h1>
          <p className="muted">Scheduled collectors and one-off probes. Collected material is matched against your watchlist; only matches become leaks.</p>
        </div>
      </div>

      <NewSource onCreated={(s) => sources.setData((xs) => [...(xs || []), s])} />

      <Card title="Sources" actions={<button className="btn btn-sm btn-ghost" onClick={sources.reload}><RefreshCw size={13} /></button>}>
        <ErrorBox error={sources.error} onRetry={sources.reload} />
        {sources.loading && !sources.data && <Spinner />}
        {sources.data?.length === 0 && <Empty title="No sources configured">Add a collector above.</Empty>}
        {sources.data?.length > 0 && (
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Kind</th><th>Target</th><th>Every</th><th>Pages</th><th>Active</th><th>Last run</th><th /></tr></thead>
              <tbody>
                {sources.data.map((s) => (
                  <tr key={s.id} className={s.is_active ? '' : 'dim'}>
                    <td><Pill>{s.kind}</Pill></td>
                    <td className="mono-wrap">{s.target || <span className="muted">watchlist</span>}</td>
                    <td className="nowrap">
                      <select className="input input-sm" value={s.interval_minutes} onChange={(e) => update(s, { interval_minutes: Number(e.target.value) })}>
                        {[...new Set([15, 60, 180, 360, 720, 1440, 10080, s.interval_minutes])].sort((a, b) => a - b).map((m) => (
                          <option key={m} value={m}>{m >= 1440 ? `${m / 1440}d` : m >= 60 ? `${m / 60}h` : `${m}m`}</option>
                        ))}
                      </select>
                    </td>
                    <td>{s.max_pages}</td>
                    <td><Toggle checked={s.is_active} onChange={(v) => update(s, { is_active: v })} /></td>
                    <td className="nowrap">{relTime(s.last_run_at)}</td>
                    <td className="nowrap">
                      <button className="btn btn-sm" onClick={() => runNow(s)}><Play size={13} /> Run now</button>
                      <button className="icon-btn danger" onClick={() => remove(s)} aria-label="Delete"><Trash2 size={15} /></button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <p className="small faint">Need a one-off lookup instead? Use <Link className="link" to="/recon">Probes</Link>.</p>

      <Card title="Recent runs" actions={
        <>
          {anyRunning && <Pill tone="warn">auto-refreshing</Pill>}
          <button className="btn btn-sm btn-ghost" onClick={runs.reload}><RefreshCw size={13} /></button>
        </>
      }>
        <ErrorBox error={runs.error} onRetry={runs.reload} />
        {runs.loading && !runs.data && <Spinner />}
        {runs.data?.length === 0 && <Empty title="No runs yet" />}
        {runs.data?.length > 0 && (
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Started</th><th>Kind</th><th>Query</th><th>Status</th><th>Results</th><th>New leaks</th><th>Tor</th><th>Error</th></tr></thead>
              <tbody>
                {runs.data.map((r) => (
                  <tr key={r.id} className="clickable" onClick={() => setRunId(r.id)}>
                    <td className="nowrap">{fmtDate(r.started_at)}</td>
                    <td><Pill>{r.kind}</Pill></td>
                    <td className="mono-wrap trunc">{r.query || '—'}</td>
                    <td><RunStatus status={r.status} /></td>
                    <td>{r.results ?? '—'}</td>
                    <td>{r.new_leaks ? <b>{r.new_leaks}</b> : r.new_leaks ?? '—'}</td>
                    <td>{r.via_tor ? <Pill tone="vip">tor</Pill> : <span className="muted">no</span>}</td>
                    <td className="error-text trunc">{r.error || ''}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {runId && <RunDetail id={runId} onClose={() => setRunId(null)} />}
    </div>
  );
}

function RunStatus({ status }) {
  const tone = status === 'ok' ? 'ok' : status === 'error' ? 'critical' : 'warn';
  return <Pill tone={tone}>{status}</Pill>;
}

function NewSource({ onCreated }) {
  const [kind, setKind] = useState('ahmia');
  const [target, setTarget] = useState('');
  const [interval, setInterval_] = useState(360);
  const [pages, setPages] = useState(10);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const toast = useToast();
  const needs = NEEDS_TARGET.has(kind);

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const s = await api.addSource({ kind, target: target.trim() || null, interval_minutes: interval, max_pages: pages });
      onCreated(s);
      setTarget('');
      toast(`Source ${s.kind} added`, 'ok');
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card title="Add a source">
      <form className="form-inline" onSubmit={submit}>
        <label className="field">
          <span>Kind</span>
          <select className="input" value={kind} onChange={(e) => setKind(e.target.value)}>
            {KINDS.map((k) => <option key={k}>{k}</option>)}
          </select>
        </label>
        <label className="field grow">
          <span>Target {needs && <b className="req">*</b>}</span>
          <input className="input" required={needs} maxLength={512} placeholder={TARGET_HINT[kind]} value={target}
            onChange={(e) => setTarget(e.target.value)} />
        </label>
        <label className="field">
          <span>Interval (min)</span>
          <input className="input w-num" type="number" min={15} max={10080} value={interval} onChange={(e) => setInterval_(Number(e.target.value))} />
        </label>
        <label className="field">
          <span>Max pages</span>
          <input className="input w-num" type="number" min={1} max={50} value={pages} onChange={(e) => setPages(Number(e.target.value))} />
        </label>
        <div className="field"><span>&nbsp;</span>
          <button className="btn btn-primary" disabled={busy || (needs && !target.trim())}><Plus size={14} /> Add</button>
        </div>
      </form>
      <ErrorBox error={error} />
    </Card>
  );
}

function RunDetail({ id, onClose }) {
  const run = useAsync(() => api.run(id), [id]);
  const r = run.data;
  return (
    <Modal title="Run detail" onClose={onClose} wide>
      <ErrorBox error={run.error} onRetry={run.reload} />
      {run.loading && !r && <Spinner />}
      {r && (
        <>
          <KV rows={[
            ['Kind', r.kind],
            ['Query', r.query],
            ['Status', <RunStatus key="s" status={r.status} />],
            ['Results', r.results],
            ['New leaks', r.new_leaks],
            ['Via Tor', r.via_tor ? 'yes' : 'no'],
            ['Started', fmtDate(r.started_at)],
            ['Finished', fmtDate(r.finished_at)],
            ['Error', r.error],
          ]} />
          <h4>Report</h4>
          {r.report && Object.keys(r.report).length ? <JsonView data={r.report} /> : <span className="muted">No report recorded</span>}
          {r.status === 'running' && <button className="btn btn-sm mt" onClick={run.reload}><RefreshCw size={13} /> Refresh</button>}
        </>
      )}
    </Modal>
  );
}
