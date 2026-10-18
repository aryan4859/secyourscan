import React, { useState } from 'react';
import { FileDown, KeyRound } from 'lucide-react';
import { api } from '../api';
import { CopyButton, ErrorBox, Modal } from './ui';

// GET /leaks/export/dossier returns a signed PDF. The SHA-256 of the PDF and
// its signature come back as X-Dossier-SHA256 / X-Dossier-Signature; they are
// shown here so the analyst can record them alongside the file.
export default function DossierDialog({ onClose }) {
  const [minSeverity, setMinSeverity] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);

  const generate = async () => {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const h = await api.exportDossier(minSeverity);
      setResult({ sha256: h.get('X-Dossier-SHA256'), signature: h.get('X-Dossier-Signature') });
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal title="Export signed dossier" onClose={onClose} footer={
      <>
        <button className="btn" onClick={() => api.downloadPublicKey().catch(setError)}>
          <KeyRound size={14} /> Public key
        </button>
        <button className="btn btn-primary" onClick={generate} disabled={busy}>
          <FileDown size={14} /> {busy ? 'Generating…' : 'Generate PDF'}
        </button>
      </>
    }>
      <p className="muted">A PDF of your organisation's leaks, ordered by severity (up to 5,000 records). The generation is recorded in the audit log.</p>
      <label className="field">
        <span>Minimum severity: <b>{minSeverity}</b></span>
        <input type="range" min="0" max="100" step="5" value={minSeverity} onChange={(e) => setMinSeverity(Number(e.target.value))} />
      </label>
      <ErrorBox error={error} />
      {result && (
        <div className="dossier-result">
          <div className="ok-line">Downloaded. Keep these values with the file:</div>
          <label className="field">
            <span>SHA-256 {result.sha256 && <CopyButton text={result.sha256} />}</span>
            <code className="mono-wrap">{result.sha256 || 'not provided by server'}</code>
          </label>
          <label className="field">
            <span>Signature {result.signature && <CopyButton text={result.signature} />}</span>
            <code className="mono-wrap">{result.signature || 'not provided by server'}</code>
          </label>
        </div>
      )}
    </Modal>
  );
}
