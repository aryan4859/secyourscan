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

export function Logo() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" aria-hidden="true">
      <circle cx="12" cy="12" r="9.5" />
      <path d="M12 12l6-6" />
      <path d="M7.5 16.5a6.4 6.4 0 0 1 9-9" />
      <circle cx="12" cy="12" r="1.3" fill="currentColor" stroke="none" />
    </svg>
  );
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
        <Link className="logo" href="/" aria-label="SecYourScan home"><Logo /> SecYourScan</Link>
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
