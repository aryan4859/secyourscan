import React, { useState } from 'react';
import { FlaskConical, Plus, Trash2 } from 'lucide-react';
import { api } from '../api';
import { Card, Empty, ErrorBox, Pill, Spinner, fmtDate, useAsync, useToast } from '../components/ui';

const TEMPLATE = `rule acme_internal_hostname
{
    meta:
        description = "Internal hostname of acme"
        severity = 70
    strings:
        $a = "corp.acme.example.com" nocase
    condition:
        $a
}`;

export default function Rules() {
  const rules = useAsync(() => api.yaraRules(), []);
  const toast = useToast();
  const [name, setName] = useState('');
  const [content, setContent] = useState(TEMPLATE);
  const [sample, setSample] = useState('');
  const [saveErr, setSaveErr] = useState(null);
  const [test, setTest] = useState(null);
  const [testErr, setTestErr] = useState(null);
  const [busy, setBusy] = useState(null);
  const [expanded, setExpanded] = useState(null);

  const save = async (e) => {
    e.preventDefault();
    setBusy('save');
    setSaveErr(null);
    try {
      const r = await api.createYara({ name: name.trim(), content });
      rules.setData((xs) => [...(xs || []), r]);
      setName('');
      toast(`Rule ${r.name} saved`, 'ok');
    } catch (err) {
      setSaveErr(err);
    } finally {
      setBusy(null);
    }
  };

  const runTest = async () => {
    setBusy('test');
    setTest(null);
    setTestErr(null);
    try {
      setTest(await api.testYara(content, sample));
    } catch (err) {
      setTestErr(err);
    } finally {
      setBusy(null);
    }
  };

  const remove = async (r) => {
    if (!window.confirm(`Delete rule ${r.name}?`)) return;
    try {
      await api.deleteYara(r.id);
      rules.setData((xs) => xs.filter((x) => x.id !== r.id));
    } catch (e) {
      toast(e.message, 'error');
    }
  };

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Detection rules</h1>
          <p className="muted">YARA rules run on every ingested item. Global rules ship with the server; tenant rules are yours.</p>
        </div>
      </div>

      <div className="grid-2">
        <Card title="Rule editor">
          <form className="stack" onSubmit={save}>
            <label className="field">
              <span>Name (identifier)</span>
              <input className="input mono" required maxLength={64} pattern="[A-Za-z_][A-Za-z0-9_]*" placeholder="acme_internal_hostname"
                value={name} onChange={(e) => setName(e.target.value)} />
            </label>
            <label className="field">
              <span>Rule source</span>
              <textarea className="input code" rows={12} spellCheck={false} minLength={10} maxLength={50000} value={content}
                onChange={(e) => setContent(e.target.value)} />
            </label>
            <div className="btn-row">
              <button className="btn btn-primary" disabled={busy === 'save' || !name.trim() || content.length < 10}><Plus size={14} /> Save rule</button>
            </div>
            <ErrorBox error={saveErr} />
          </form>
        </Card>

        <Card title="Test against sample text">
          <div className="stack">
            <p className="muted small">Compiles the rule in the editor and runs it on the text below. Nothing is saved.</p>
            <textarea className="input code" rows={8} maxLength={200000} placeholder="Paste sample text…" value={sample}
              onChange={(e) => setSample(e.target.value)} />
            <div className="btn-row">
              <button className="btn" onClick={runTest} disabled={busy === 'test' || content.length < 10}>
                <FlaskConical size={14} /> {busy === 'test' ? 'Testing…' : 'Test rule'}
              </button>
            </div>
            <ErrorBox error={testErr} />
            {test && (
              test.valid ? (
                <div className={`test-result ${test.matches.length ? 'hit' : 'miss'}`}>
                  {test.matches.length ? <>Matched: {test.matches.map((m) => <Pill key={m} tone="rule">{m}</Pill>)}</> : 'Compiled. No match on this sample.'}
                </div>
              ) : (
                <div className="test-result bad">Compile error: <code>{test.error}</code></div>
              )
            )}
          </div>
        </Card>
      </div>

      <Card title={`Rules${rules.data ? ` (${rules.data.length})` : ''}`}>
        <ErrorBox error={rules.error} onRetry={rules.reload} />
        {rules.loading && !rules.data && <Spinner />}
        {rules.data?.length === 0 && <Empty title="No rules" />}
        {rules.data?.length > 0 && (
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Name</th><th>Scope</th><th>Active</th><th>Created</th><th /></tr></thead>
              <tbody>
                {rules.data.map((r) => (
                  <React.Fragment key={r.id}>
                    <tr className="clickable" onClick={() => setExpanded(expanded === r.id ? null : r.id)}>
                      <td className="mono">{r.name}</td>
                      <td><Pill tone={r.scope === 'global' ? 'default' : 'vip'}>{r.scope}</Pill></td>
                      <td>{r.is_active ? 'yes' : 'no'}</td>
                      <td className="nowrap">{fmtDate(r.created_at)}</td>
                      <td className="nowrap" onClick={(e) => e.stopPropagation()}>
                        <button className="btn btn-sm" onClick={() => { setContent(r.content); setName(r.scope === 'tenant' ? '' : `${r.name}_copy`); window.scrollTo({ top: 0, behavior: 'smooth' }); }}>
                          Load
                        </button>
                        {r.scope === 'tenant' && (
                          <button className="icon-btn danger" onClick={() => remove(r)} aria-label="Delete"><Trash2 size={15} /></button>
                        )}
                      </td>
                    </tr>
                    {expanded === r.id && (
                      <tr className="expand-row"><td colSpan={5}><pre className="json">{r.content}</pre></td></tr>
                    )}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
