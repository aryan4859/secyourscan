'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { AnimatePresence, motion } from 'motion/react';
import CheckForm from '../../components/CheckForm';
import { CountUp, EASE, GrowBar, Reveal, WordsUp } from '../../components/motion';
import { clientApi } from '../../lib/api';
import { PASSWORD_RISK, SENSITIVE, comma, fmtDate, isDomain, isEmail, num } from '../../lib/format';

const STORAGE = [
  ['PlainText', 'Plain text', 'var(--bad)'],
  ['EasyToCrack', 'Weak hash (easy to crack)', 'var(--accent)'],
  ['StrongHash', 'Strong hash', 'var(--ok)'],
  ['Unknown', 'Unknown', 'var(--ink-3)'],
];

export default function CheckClient() {
  const params = useSearchParams();
  const router = useRouter();
  const kind = params.has('domain') ? 'domain' : 'email';
  const value = (params.get(kind) || '').trim().toLowerCase();
  const [state, setState] = useState({ status: 'idle' });
  const seq = useRef(0);

  const run = useCallback(async (k, v) => {
    const mine = ++seq.current;
    setState({ status: 'loading', kind: k, value: v });
    try {
      const data = k === 'email' ? await loadEmail(v) : await loadDomain(v);
      if (mine === seq.current) setState({ status: 'done', kind: k, value: v, data });
    } catch (e) {
      if (mine === seq.current) setState({ status: 'error', kind: k, value: v, error: e.message });
    }
  }, []);

  useEffect(() => {
    if (value && (kind === 'email' ? isEmail(value) : isDomain(value))) run(kind, value);
  }, [kind, value, run]);

  return (
    <>
      <section className="page-top">
        <div className="wrap">
          <WordsUp text="Has it been in a breach?" />
          <Reveal as="p" className="lede" delay={0.25}>
            Check an email address to see every known breach that included it and what leaked. Check a company domain for a
            summary across all of its addresses.
          </Reveal>
          <Reveal delay={0.35}>
            <CheckForm kind={kind} value={value} busy={state.status === 'loading'}
              note="Your search goes to the SecYourScan breach API over HTTPS."
              onSubmit={(k, v) => (k === kind && v === value
                ? run(k, v) // same URL: the effect won't fire, so re-run directly
                : router.replace(`/check?${k}=${encodeURIComponent(v)}`, { scroll: false }))} />
          </Reveal>
        </div>
      </section>

      <div className="wrap" aria-live="polite">
        <AnimatePresence mode="wait">
          {state.status === 'loading' && (
            <motion.div key="loading" className="scanning" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
              <span className="scan-line" /> Looking up {state.value}
            </motion.div>
          )}
          {state.status === 'error' && (
            <motion.div key="error" className="verdict" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}>
              <p className="big">We couldn’t finish that check.</p>
              <p className="sub">{state.error || 'The breach API did not answer.'}</p>
            </motion.div>
          )}
          {state.status === 'done' && (
            <motion.div key={`${state.kind}:${state.value}`} initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              transition={{ duration: 0.3 }}>
              {state.kind === 'email' ? <EmailReport email={state.value} {...state.data} /> : <DomainReport domain={state.value} d={state.data} />}
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </>
  );
}

// ── data ─────────────────────────────────────────────────────────────────────

async function loadEmail(email) {
  const [check, analytics] = await Promise.all([
    clientApi.checkEmail(email),
    clientApi.breachAnalytics(email).catch(() => null), // detail is a bonus; the yes/no must not depend on it
  ]);
  const names = Array.isArray(check.breaches) ? (check.breaches[0] || []) : [];
  return { names, analytics };
}

async function loadDomain(domain) {
  const r = await clientApi.domainSummary(domain);
  return r?.sendDomains?.breaches_details?.[0] || null;
}

/** The API nests categories → items as {name: "data_Passwords", value: n}. */
function flattenExposed(x) {
  return (x?.[0]?.children || []).map((c) => ({
    name: String(c.name || '').replace(/^[^\p{L}]+/u, '').trim(),
    items: (c.children || []).map((i) => ({ name: String(i.name || '').replace(/^data_/, ''), value: num(i.value) }))
      .filter((i) => i.value > 0).sort((a, b) => b.value - a.value),
  })).filter((c) => c.items.length);
}

// ── pieces ───────────────────────────────────────────────────────────────────

function Verdict({ tone, children, sub }) {
  return (
    <div className="verdict">
      <motion.p className={`big ${tone}`} initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.7, ease: EASE }}>
        {children}
      </motion.p>
      {sub && <motion.p className="sub" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.2, duration: 0.6 }}>{sub}</motion.p>}
    </div>
  );
}

function Figures({ items }) {
  return (
    <motion.div className="figures" initial="hidden" animate="show" variants={{ show: { transition: { staggerChildren: 0.08, delayChildren: 0.25 } } }}>
      {items.map(([label, value, bad, suffix]) => (
        <motion.div key={label} variants={{ hidden: { opacity: 0, y: 10 }, show: { opacity: 1, y: 0, transition: { duration: 0.6, ease: EASE } } }}>
          <div className="label">{label}</div>
          <div className={`v ${bad ? 'bad' : ''}`}>{typeof value === 'number' ? <CountUp value={value} duration={1.1} /> : value}{suffix}</div>
        </motion.div>
      ))}
    </motion.div>
  );
}

function Todo({ steps }) {
  return <ol className="todo">{steps.map((s, i) => <Reveal as="li" key={s} delay={0.1 + i * 0.06}><span>{s}</span></Reveal>)}</ol>;
}

// ── email report ─────────────────────────────────────────────────────────────

function EmailReport({ email, names, analytics }) {
  if (!names.length) {
    return (
      <div className="report-end">
        <Verdict tone="ok" sub="That isn’t a guarantee, only that none of the breaches in our index contain it. Use a different password for every site and turn on two-factor sign-in anyway.">
          Good news. {email} isn’t in any breach we know of.
        </Verdict>
        <p className="sub"><Link className="arrow-link" href="/breaches">See which breaches we index <span>→</span></Link></p>
      </div>
    );
  }
  const m = analytics?.BreachMetrics;
  const details = analytics?.ExposedBreaches?.breaches_details || [];
  const risk = m?.risk?.[0];
  const pw = m?.passwords_strength?.[0] || {};
  const weak = num(pw.PlainText) + num(pw.EasyToCrack);
  const pastes = num(analytics?.PastesSummary?.cnt);
  const exposed = flattenExposed(m?.xposed_data);
  const has = (re) => exposed.some((c) => c.items.some((i) => re.test(i.name)));

  const steps = [];
  if (has(/password/i)) {
    steps.push(weak
      ? 'Change the password on any site where you used the same one as a breached site. Some of yours leaked in plain text or a weak hash.'
      : 'Change the password on any site where you reused one from a breached site.');
  }
  steps.push('Turn on two-factor sign-in for email, banking and work accounts first.');
  steps.push('Use a password manager so every site gets its own password.');
  steps.push('Expect phishing that mentions these services by name, and don’t click through from email.');
  if (has(/phone/i)) steps.push('Your phone number leaked too: ask your carrier for a SIM-swap PIN and be wary of texts with links.');

  return (
    <>
      <Verdict tone="bad" sub={risk
        ? `Our risk rating for this address is ${risk.risk_label.toLowerCase()} (${risk.risk_score}/100), based on how many breaches it’s in, what leaked and how passwords were stored.`
        : 'Here is what we know about where it was exposed.'}>
        {email} appears in {comma(names.length)} breach{names.length === 1 ? '' : 'es'}.
      </Verdict>
      <Figures items={[
        ['Breaches', names.length, true],
        ['Risk', risk ? risk.risk_score : '—', risk && risk.risk_score >= 60, risk ? '/100' : ''],
        ['Breaches with weak passwords', weak, weak > 0],
        ['Paste appearances', pastes, pastes > 0],
      ]} />

      <div className="report-grid">
        {exposed.length > 0 && (
          <Reveal>
            <h2>What was exposed</h2>
            <div className="exposed">
              {exposed.map((c) => (
                <div key={c.name}>
                  <div className="label">{c.name}</div>
                  <div className="chips">
                    {c.items.map((i) => (
                      <span key={i.name} className={`chip ${SENSITIVE.test(i.name) ? 'hot' : ''}`} title={`${i.name} leaked in ${i.value} breach${i.value === 1 ? '' : 'es'}`}>
                        {i.name} · {i.value}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </Reveal>
        )}
        <Reveal delay={0.1}><h2>What to do now</h2><Todo steps={steps} /></Reveal>
        {m?.passwords_strength && <Reveal><h2>How the leaked passwords were stored</h2><StorageBar pw={pw} /></Reveal>}
        {m?.yearwise_details && <Reveal delay={0.1}><h2>Breaches by year</h2><YearBars y={m.yearwise_details[0]} /></Reveal>}
      </div>

      {details.length > 0 ? <BreachTable rows={details} /> : (
        <div className="chips report-end">{names.map((n) => <span key={n} className="chip">{n}</span>)}</div>
      )}
    </>
  );
}

function StorageBar({ pw }) {
  const total = STORAGE.reduce((n, [k]) => n + num(pw[k]), 0) || 1;
  return (
    <>
      <div className="stack-bar" role="img" aria-label={STORAGE.map(([k, l]) => `${l}: ${num(pw[k])}`).join(', ')}>
        {STORAGE.map(([k, , c], i) => (
          <motion.span key={k} style={{ background: c }} initial={{ width: 0 }} whileInView={{ width: `${(num(pw[k]) / total) * 100}%` }}
            viewport={{ once: true }} transition={{ duration: 0.8, delay: 0.15 + i * 0.12, ease: EASE }} />
        ))}
      </div>
      <ul className="legend">
        {STORAGE.map(([k, l, c]) => <li key={k}><i style={{ background: c }} />{l}<span className="v">{comma(pw[k])}</span></li>)}
      </ul>
    </>
  );
}

function YearBars({ y }) {
  const years = Object.entries(y || {}).map(([k, v]) => [k.replace(/^y/, ''), num(v)]).sort((a, b) => a[0] - b[0]);
  const first = years.findIndex(([, v]) => v > 0);
  const shown = first > 0 ? years.slice(first) : years;
  const max = Math.max(1, ...shown.map(([, v]) => v));
  return (
    <>
      <div className="years" role="img" aria-label={shown.map(([yr, v]) => `${yr}: ${v}`).join(', ')}>
        {shown.map(([yr, v], i) => (
          <span key={yr} className="year" title={`${yr}: ${v} breach${v === 1 ? '' : 'es'}`}>
            <GrowBar axis="y" pct={(v / max) * 100} delay={i * 0.03} className="year-fill" />
          </span>
        ))}
      </div>
      <div className="years-axis"><span>{shown[0]?.[0]}</span><span>{shown[shown.length - 1]?.[0]}</span></div>
    </>
  );
}

function BreachTable({ rows }) {
  const [all, setAll] = useState(false);
  const sorted = [...rows].sort((a, b) => num(b.xposed_date) - num(a.xposed_date) || num(b.xposed_records) - num(a.xposed_records));
  const shown = all ? sorted : sorted.slice(0, 20);
  return (
    <Reveal className="report-end">
      <h2 className="h-sub">Every breach it’s in</h2>
      <div className="table-wrap">
        <table className="data">
          <thead><tr><th>Breach</th><th className="num">Year</th><th className="num">Records</th><th>Passwords</th></tr></thead>
          <tbody>
            {shown.map((b, i) => {
              const [label, bad] = PASSWORD_RISK[String(b.password_risk || 'unknown').toLowerCase()] || [b.password_risk, false];
              return (
                <motion.tr key={b.breach} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i >= 20 ? (i - 20) * 0.01 : 0 }}>
                  <td>
                    <div>{b.breach}{b.domain && <span className="faint small"> · {b.domain}</span>}</div>
                    <div className="desc">{String(b.xposed_data || '').split(';').map((s) => s.trim()).filter(Boolean).join(', ')}</div>
                  </td>
                  <td className="num">{b.xposed_date || '—'}</td>
                  <td className="num">{comma(b.xposed_records)}</td>
                  <td><span className={`small ${bad ? 'bad-text' : 'faint'}`}>{label}</span></td>
                </motion.tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {!all && sorted.length > 20 && <p className="more"><button className="btn quiet" onClick={() => setAll(true)}>Show all {sorted.length}</button></p>}
    </Reveal>
  );
}

// ── domain report ────────────────────────────────────────────────────────────

function DomainReport({ domain, d }) {
  if (!d || !num(d.breach_count)) {
    return (
      <div className="report-end">
        <Verdict tone="ok" sub="None of the breaches in our index contain addresses at this domain. Leaks of your systems, credentials on paste sites and lookalike domains are a different question. That’s what the platform watches.">
          No known breaches for {domain}.
        </Verdict>
      </div>
    );
  }
  return (
    <div className="report-end">
      <Verdict tone="bad" sub={d.breach_last_seen ? `Most recently seen ${fmtDate(d.breach_last_seen)}.` : null}>
        Addresses at {domain} appear in {comma(d.breach_count)} breach{num(d.breach_count) === 1 ? '' : 'es'}.
      </Verdict>
      <Figures items={[
        ['Breaches', num(d.breach_count), true],
        ['Exposed addresses', num(d.breach_emails), num(d.breach_emails) > 0],
        ['Total exposures', num(d.breach_total), false],
        ['Paste appearances', num(d.breach_pastes), num(d.breach_pastes) > 0],
      ]} />
      <div className="two-col">
        <Reveal>
          <h2 className="h-sub">Which addresses, and which breaches?</h2>
          <p className="muted">We only show that detail to the domain’s owner. In the platform, prove you control the domain with a DNS
            TXT record, and you get the full list. New exposures alert you as they appear.</p>
          <p><Link className="btn" href="/#pricing">Set up monitoring</Link></p>
        </Reveal>
        <Reveal delay={0.1}>
          <h2 className="h-sub">In the meantime</h2>
          <Todo steps={[
            'Force a password reset for staff who reuse work passwords elsewhere.',
            'Require two-factor sign-in on email, VPN and remote access.',
            'Warn staff to expect targeted phishing that uses leaked personal details.',
          ]} />
        </Reveal>
      </div>
    </div>
  );
}
