'use client';

import { useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import { AnimatePresence, motion } from 'motion/react';
import { EASE } from './motion';
import { isDomain, isEmail } from '../lib/format';

const KINDS = {
  email: { label: 'Email address', placeholder: 'you@company.com', type: 'email', auto: 'email' },
  domain: { label: 'Company domain', placeholder: 'company.com', type: 'text', auto: 'off' },
};

/**
 * Email / domain check form. Without `onSubmit` it navigates to
 * /check?email=… or ?domain=…; the check page passes `onSubmit` to run in place.
 */
export default function CheckForm({ kind: initialKind = 'email', value: initialValue = '', onSubmit, busy = false, note }) {
  const [kind, setKind] = useState(initialKind);
  const [value, setValue] = useState(initialValue);
  const [error, setError] = useState('');
  const router = useRouter();
  const input = useRef(null);

  useEffect(() => { setKind(initialKind); setValue(initialValue); }, [initialKind, initialValue]);

  const submit = (e) => {
    e.preventDefault();
    let v = value.trim().toLowerCase();
    if (kind === 'domain') v = v.replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0];
    if (!(kind === 'email' ? isEmail(v) : isDomain(v))) {
      setError(kind === 'email' ? 'That doesn’t look like an email address.' : 'That doesn’t look like a domain. Try something like company.com.');
      input.current?.focus();
      return;
    }
    setError('');
    if (onSubmit) onSubmit(kind, v);
    else router.push(`/check?${kind}=${encodeURIComponent(v)}`);
  };

  const k = KINDS[kind];
  return (
    <div className="check">
      <div className="tabs" role="tablist" aria-label="What to check">
        {Object.entries(KINDS).map(([key, { label }]) => (
          <button key={key} type="button" role="tab" aria-selected={kind === key}
            onClick={() => { setKind(key); setError(''); input.current?.focus(); }}>
            {label}
            {kind === key && <motion.span layoutId="check-tab" className="tab-underline" transition={{ duration: 0.35, ease: EASE }} />}
          </button>
        ))}
      </div>
      <form className="check-form" onSubmit={submit} noValidate>
        <label className="sr-only" htmlFor="q">{k.label}</label>
        <input id="q" ref={input} name={kind} type={k.type} autoComplete={k.auto} placeholder={k.placeholder}
          value={value} onChange={(e) => setValue(e.target.value)} />
        <button className="btn" type="submit" disabled={busy}>
          {busy ? <span className="spinner" aria-hidden="true" /> : null}
          {busy ? 'Checking' : 'Check'}
        </button>
      </form>
      <AnimatePresence>
        {error && (
          <motion.p className="form-error" role="alert" initial={{ opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}>
            {error}
          </motion.p>
        )}
      </AnimatePresence>
      <p className="form-note">{note || 'Free, no account. Your search goes to the SecYourScan breach API over HTTPS.'}</p>
    </div>
  );
}
