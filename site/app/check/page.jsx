import { Suspense } from 'react';
import CheckClient from './CheckClient';

export const metadata = {
  title: 'Check an email or domain',
  description: 'See which known data breaches include an email address or company domain, what was exposed, and what to do about it.',
  robots: { index: false },
};

export default function CheckPage() {
  return (
    <Suspense fallback={null}>
      <CheckClient />
    </Suspense>
  );
}
