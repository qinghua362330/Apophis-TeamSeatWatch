type IconName = 'accounts' | 'workspaces' | 'batches' | 'operation' | 'cards' | 'redemptions' | 'rotation' | 'degradation' | 'proxy' | 'search' | 'upload' | 'download' | 'refresh' | 'sun' | 'moon' | 'logout' | 'arrow-left' | 'arrow-right' | 'check' | 'clock' | 'selected' | 'lock' | 'sidebar-collapse' | 'sidebar-expand';

const paths: Record<IconName, string[]> = {
  accounts: ['M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2', 'M16 3a4 4 0 0 1 0 8', 'M22 21v-2a4 4 0 0 0-3-3.87', 'M13 7a4 4 0 1 1-8 0 4 4 0 0 1 8 0Z'],
  workspaces: ['M3 3h7v7H3Z', 'M14 3h7v7h-7Z', 'M3 14h7v7H3Z', 'M14 14h7v7h-7Z'],
  batches: ['m12 3 10 5-10 5L2 8Z', 'm2 12 10 5 10-5', 'm2 16 10 5 10-5'],
  operation: ['m8 4 12 8-12 8Z'],
  cards: ['M4 5h16a1 1 0 0 1 1 1v4a2 2 0 0 0 0 4v4a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1v-4a2 2 0 0 0 0-4V6a1 1 0 0 1 1-1Z', 'M15 5v3m0 3v2m0 3v3'],
  redemptions: ['M5 3v18l3-2 4 2 4-2 3 2V3Z', 'M9 7h6', 'M9 11h6', 'M9 15h3'],
  rotation: ['M20 7a9 9 0 0 0-15-2L2 8', 'M2 3v5h5', 'M4 17a9 9 0 0 0 15 2l3-3', 'M22 21v-5h-5'],
  degradation: ['M12 3 3 19h18Z', 'M12 9v5', 'M12 18h.01'],
  proxy: ['M4 7h16', 'M7 4v6', 'M17 4v6', 'M4 10h16v10H4Z', 'M8 14h2m4 0h2'],
  search: ['M19 19l-4-4', 'M17 10a7 7 0 1 1-14 0 7 7 0 0 1 14 0Z'],
  upload: ['M12 16V3', 'm7 8 5-5 5 5', 'M4 16v4a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-4'],
  download: ['M12 3v13', 'm7 11 5 5 5-5', 'M4 16v4a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-4'],
  refresh: ['M20 7a9 9 0 1 0 1 9', 'M20 3v5h-5'],
  sun: ['M16 12a4 4 0 1 1-8 0 4 4 0 0 1 8 0Z', 'M12 2v2m0 16v2M2 12h2m16 0h2M5 5l1.5 1.5m11 11L19 19M5 19l1.5-1.5m11-11L19 5'],
  moon: ['M21 13a9 9 0 1 1-10-10 7 7 0 0 0 10 10Z'],
  logout: ['M9 4H4v16h5', 'M9 12h12', 'm17 8 4 4-4 4'],
  'arrow-left': ['M20 12H4', 'm10 6-6 6 6 6'],
  'arrow-right': ['M4 12h16', 'm14 6 6 6-6 6'],
  check: ['M21 11v1a9 9 0 1 1-5.3-8.2', 'm9 11 3 3L22 4'],
  clock: ['M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z', 'M12 7v5l3 2'],
  selected: ['M9 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-4', 'm9 11 3 3L21 5'],
  lock: ['M5 10h14v11H5Z', 'M8 10V6a4 4 0 0 1 8 0v4', 'M12 14v3'],
  'sidebar-collapse': ['M3 3h18v18H3Z', 'M9 3v18', 'm16 9-3 3 3 3'],
  'sidebar-expand': ['M3 3h18v18H3Z', 'M9 3v18', 'm14 9 3 3-3 3'],
};

export default function OwnerIcon({ name, size = 20 }: { name: IconName; size?: number }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false">
    {paths[name].map((path) => <path d={path} key={path} />)}
  </svg>;
}
