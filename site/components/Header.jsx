'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { AnimatePresence, motion } from 'motion/react';
import { EASE } from './motion';

const LINKS = [
  ['/#product', 'Product'],
  ['/check', 'Check an email'],
  ['/breaches', 'Breach directory'],
  ['/#pricing', 'Pricing'],
];

// One corner bracket of the mark; the other three are the same path rotated.
const BRACKET = 'M0 18A18 18 0 0 1 18 0H43.2V19H28A9 9 0 0 0 19 28V43.2H0Z';

/** The SecYourScan mark: four brackets around a red target. Colours come
 *  from --logo-navy / --logo-blue / --logo-red so it reads in both themes. */
export function Logo() {
  return (
    <svg className="brand-mark" viewBox="0 0 100 100" aria-hidden="true">
      <path d={BRACKET} fill="var(--logo-navy)" />
      <path d={BRACKET} fill="var(--logo-blue)" transform="rotate(90 50 50)" />
      <path d={BRACKET} fill="var(--logo-navy)" transform="rotate(180 50 50)" />
      <path d={BRACKET} fill="var(--logo-blue)" transform="rotate(270 50 50)" />
      <path d="M50 11v17M50 72v17M11 50h17M72 50h17" stroke="var(--logo-navy)" strokeWidth="3" strokeLinecap="round" fill="none" />
      <rect className="brand-target" x="43.5" y="43.5" width="13" height="13" rx="1.8" fill="var(--logo-red)" />
    </svg>
  );
}

/** Mark plus wordmark, as in the brand artwork: "SecYour" in ink, "Scan" in blue. */
export function Wordmark() {
  return <span className="wordmark">SecYour<span>Scan</span></span>;
}

export default function Header() {
  const path = usePathname();
  const [open, setOpen] = useState(false);
  useEffect(() => setOpen(false), [path]);

  const nav = LINKS.map(([href, label]) => (
    <Link key={href} href={href} aria-current={href === path ? 'page' : undefined} onClick={() => setOpen(false)}>
      {label}
      {href === path && <motion.span layoutId="nav-underline" className="nav-underline" transition={{ duration: 0.4, ease: EASE }} />}
    </Link>
  ));

  return (
    <header className="site-head">
      <div className="wrap">
        <Link className="logo" href="/" aria-label="SecYourScan home"><Logo /><Wordmark /></Link>
        <nav className="site-nav" aria-label="Main">{nav}</nav>
        <button className="menu-btn" aria-expanded={open} aria-controls="mobile-nav" onClick={() => setOpen((v) => !v)}>
          {open ? 'Close' : 'Menu'}
        </button>
      </div>
      <AnimatePresence>
        {open && (
          <motion.nav id="mobile-nav" className="mobile-nav" aria-label="Main"
            initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.35, ease: EASE }}>
            <div className="wrap">{nav}</div>
          </motion.nav>
        )}
      </AnimatePresence>
    </header>
  );
}
