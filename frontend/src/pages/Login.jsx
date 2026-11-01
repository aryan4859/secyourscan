import React, { useEffect, useState } from 'react';
import { ArrowRight, Lock } from 'lucide-react';
import { api } from '../api';
import BrandMark, { Wordmark } from '../components/BrandMark';
import { ErrorBox } from '../components/ui';

const OK = new Set(['ok', 'enabled', 'configured']);

export default function Login({ onLoggedIn }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [health, setHealth] = useState(null);

  // /system/health is unauthenticated and names no hosts, so it is safe to show here.
  useEffect(() => {
    api.health().then(setHealth).catch(() => setHealth(null));
  }, []);

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.login(email.trim(), password);
      await onLoggedIn();
    } catch (err) {
      setError(err.status === 429 ? 'Too many attempts. Wait a minute and try again.' : err);
      setBusy(false);
    }
  };

  return (
    <div className="login-wrap">
      <section className="login-hero">
        <div className="login-brand">
          <BrandMark size={34} />
          <span className="brand-text"><Wordmark /><span className="brand-sub">Exposure monitoring</span></span>
        </div>
        <div className="login-pitch">
          <div className="login-eyebrow">Threat exposure · your own assets</div>
          <h1 className="login-title">See what leaked <span>before</span> it is used.</h1>
          <p className="login-lede">Breach, paste and dark-web collection over Tor, scored and triaged against your watchlist, with a tamper-evident audit trail.</p>
        </div>
        {health?.components && (
          <div className="login-telemetry">
            <div className="login-eyebrow">Platform status</div>
            <ul>
              {Object.entries(health.components).map(([k, v]) => (
                <li key={k}>
                  <span>{k.replace(/_/g, ' ')}</span>
                  <span className={OK.has(v) ? 'chain-ok' : v === 'disabled' ? 'faint' : 'chain-bad'}>
                    <span className={`dot ${OK.has(v) ? 'dot-ok' : v === 'disabled' ? '' : 'dot-bad'}`} /> {v}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </section>
      <section className="login-side">
        <form className="login-form" onSubmit={submit}>
          <div>
            <h2 className="login-form-title">Sign in</h2>
            <p className="muted small">Use the account your administrator created for you.</p>
          </div>
          <label className="field">
            <span>Email</span>
            <input className="input" type="email" autoComplete="username" autoFocus required value={email}
              onChange={(e) => setEmail(e.target.value)} />
          </label>
          <label className="field">
            <span>Password</span>
            <input className="input" type="password" autoComplete="current-password" required value={password}
              onChange={(e) => setPassword(e.target.value)} />
          </label>
          <ErrorBox error={error} />
          <button className="btn btn-primary btn-block" disabled={busy}>
            {busy ? 'Signing in…' : <>Sign in <ArrowRight size={15} /></>}
          </button>
          <p className="login-note"><Lock size={13} /> Session held in an HTTP-only cookie. Every sign-in attempt is audited.</p>
        </form>
      </section>
    </div>
  );
}
