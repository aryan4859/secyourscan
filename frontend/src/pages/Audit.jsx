import React, { useState } from 'react';
import { Download, ShieldCheck, ShieldX } from 'lucide-react';
import { api } from '../api';
import useDebounced from '../useDebounced';
import { Card, Empty, ErrorBox, Spinner, fmtDate, useAsync, useToast } from '../components/ui';

const PAGE = 50;

export default function Audit() {
  const [offset, setOffset] = useState(0);
  const [action, setAction] = useState('');
  const debouncedAction = useDebounced(action.trim().toUpperCase(), 300);
  const rows = useAsync(() => api.audit({ limit: PAGE, offset, action: debouncedAction || undefined }), [offset, debouncedAction]);
  const [verify, setVerify] = useState(null);
  const [verifyErr, setVerifyErr] = useState(null);
  const [busy, setBusy] = useState(false);
  const toast = useToast();

  const runVerify = async () => {
    setBusy(true);
    setVerify(null);
    setVerifyErr(null);
    try {
      setVerify(await api.verifyAudit());
    } catch (e) {
      setVerifyErr(e);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Audit log</h1>
          <p className="muted">Hash-chained record of every sign-in, probe, export, evidence download and change.</p>
        </div>
        <div className="btn-row">
          <button className="btn" onClick={runVerify} disabled={busy}><ShieldCheck size={14} /> {busy ? 'Verifying…' : 'Verify chain'}</button>
          <button className="btn" onClick={() => api.exportAudit().catch((e) => toast(e.message, 'error'))}><Download size={14} /> Export CSV</button>
        </div>
      </div>

      <ErrorBox error={verifyErr} />
      {verify && (
        verify.valid ? (
          <div className="verify ok"><ShieldCheck size={18} /> Chain intact: {verify.checked} entries verified.</div>
        ) : (
          <div className="verify bad">
            <ShieldX size={18} /> Chain broken at entry <b>#{verify.broken_at}</b> ({verify.reason} mismatch) after {verify.checked} valid entries.
          </div>
        )
      )}

      <Card title="Entries" actions={
        <input className="input input-sm" placeholder="Filter by action, e.g. LOGIN" value={action}
          onChange={(e) => { setAction(e.target.value); setOffset(0); }} />
      }>
        <ErrorBox error={rows.error} onRetry={rows.reload} />
        {rows.loading && !rows.data && <Spinner />}
        {rows.data?.length === 0 && <Empty title="No audit entries" />}
        {rows.data?.length > 0 && (
          <div className={`table-wrap ${rows.loading ? 'is-loading' : ''}`}>
            <table className="table compact">
              <thead><tr><th>#</th><th>Time</th><th>Action</th><th>Actor</th><th>Resource</th><th>IP</th><th>Details</th><th>Hash</th></tr></thead>
              <tbody>
                {rows.data.map((a) => (
                  <tr key={a.id}>
                    <td className="mono">{a.id}</td>
                    <td className="nowrap">{fmtDate(a.timestamp)}</td>
                    <td><span className={`action-tag ${/FAIL|DELETE|REVOKE|EVIDENCE/.test(a.action) ? 'hot' : ''}`}>{a.action}</span></td>
                    <td className="mono trunc" title={a.user_id}>{a.user_id || '—'}</td>
                    <td className="trunc" title={a.resource_id}>{a.resource_type ? `${a.resource_type}:${(a.resource_id || '').slice(0, 8)}` : '—'}</td>
                    <td className="mono">{a.ip_address || '—'}</td>
                    <td className="mono details-cell" title={a.details ? JSON.stringify(a.details) : ''}>
                      {a.details ? JSON.stringify(a.details) : '—'}
                    </td>
                    <td className="mono" title={a.row_hash}>{a.row_hash?.slice(0, 10)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="pager">
          <button className="btn btn-sm" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>Newer</button>
          <span>{rows.data?.length ? `${offset + 1}–${offset + rows.data.length}` : '—'}</span>
          <button className="btn btn-sm" disabled={(rows.data?.length || 0) < PAGE} onClick={() => setOffset(offset + PAGE)}>Older</button>
        </div>
      </Card>
    </div>
  );
}
