export const accountsAcceptance = import.meta.env.VITE_OWNER_ACCEPTANCE_PAGE === 'accounts';

export const ownerPages = [
  { id: 'accounts', label: '账号管理' },
  { id: 'workspaces', label: '空间管理' },
  { id: 'batches', label: '批次管理' },
  { id: 'operation', label: '开始操作' },
  { id: 'cards', label: '卡密管理' },
  { id: 'redemptions', label: '兑换记录' },
  { id: 'rotation', label: '轮转管理' },
  { id: 'degradation', label: '降智事件' },
  { id: 'proxy', label: '代理管理' },
] as const;

export type OwnerPage = (typeof ownerPages)[number]['id'];
export type OwnerLocation = OwnerPage | 'channel-settings';

export function ownerLocation(hash: string): OwnerLocation {
  if (accountsAcceptance) return 'accounts';
  const id = hash.replace(/^#\/?/, '');
  if (id === 'channel-settings') return id;
  return ownerPages.find((page) => page.id === id)?.id ?? 'operation';
}

export function parentPage(location: OwnerLocation): OwnerPage {
  if (location === 'channel-settings') return 'cards';
  return location;
}

export function locationTitle(location: OwnerLocation): string {
  if (location === 'channel-settings') return '渠道设置';
  return ownerPages.find((page) => page.id === location)!.label;
}
