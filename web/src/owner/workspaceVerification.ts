import type { components } from '../generated/owner';
import type { StatusTone } from '../shared/StatusBadge';
import { workspaceSeatSummary } from './seatTypes.ts';

type Verification = components['schemas']['SelectedWorkspaceVerification'];
type WorkspaceAccessStatus = components['schemas']['SelectedWorkspaceAccessStatus'];

export function workspaceSubscriptionState(fact: Verification | null, access: WorkspaceAccessStatus | null, now: number): { label: string; tone: StatusTone; observedAt?: string | undefined } {
  if (!canShowSelectedWorkspaceReadSource(fact, access, 'subscriptions', now)) return { label: '未同步', tone: 'warning' };
  const observedAt = fact?.readSources?.find((item) => item.source === 'subscriptions')?.observedAt;
  const statuses: Record<NonNullable<Verification['subscriptionStatus']>, { label: string; tone: StatusTone }> = {
    delinquent: { label: '账单逾期', tone: 'error' },
    active: { label: '有效', tone: 'success' },
    inactive: { label: '未激活', tone: 'warning' },
    expired: { label: '已到期', tone: 'warning' },
    unknown: { label: '未获取', tone: 'warning' },
  };
  const status = fact?.subscriptionStatus;
  if (status === 'active' && fact?.activeUntil && Date.parse(fact.activeUntil) <= now) return { ...statuses.expired, observedAt };
  return { ...statuses[status ?? 'unknown'], observedAt };
}

export function canShowWorkspaceFacts(fact: Verification | null, now: number): boolean {
  return fact?.status === 'verified'
    && (fact.permission === 'read' || fact.permission === 'manage')
    && fact.accessStatus === 'readable'
    && fact.completeness === 'complete'
    && fact.expiresAt !== undefined
    && Number.isFinite(Date.parse(fact.expiresAt))
    && Date.parse(fact.expiresAt) > now;
}

export function canShowSelectedWorkspaceFacts(fact: Verification | null, access: WorkspaceAccessStatus | null, now: number): boolean {
  return access?.status === 'ready'
    && typeof access.exchangeId === 'string'
    && access.exchangeId.length > 0
    && fact?.exchangeId === access.exchangeId
    && access.expiresAt !== undefined
    && Number.isFinite(Date.parse(access.expiresAt))
    && Date.parse(access.expiresAt) > now
    && canShowWorkspaceFacts(fact, now);
}

export function canShowSelectedWorkspaceReadSource(fact: Verification | null, access: WorkspaceAccessStatus | null, source: string, now: number): boolean {
  return access?.status === 'ready'
    && typeof access.exchangeId === 'string' && access.exchangeId.length > 0
    && fact?.exchangeId === access.exchangeId
    && access.expiresAt !== undefined && Date.parse(access.expiresAt) > now
    && fact.accessStatus === 'readable'
    && (fact.status === 'verified' || fact.status === 'partial')
    && fact.expiresAt !== undefined && Date.parse(fact.expiresAt) > now
    && fact.readSources?.some((item) => item.source === source && item.permission === 'read' && item.completeness === 'complete' && item.outcome === 'operational') === true;
}

export function selectedWorkspaceOperationState(fact: Verification | null, access: WorkspaceAccessStatus | null, now: number): { ready: boolean; status: string } {
  if (!canShowSelectedWorkspaceFacts(fact, access, now)) {
    if (fact?.status === 'permission_denied' || access?.status === 'permission_denied') return { ready: false, status: '当前母号无法读取该空间' };
    if (access?.status !== 'ready' || !access.expiresAt || Date.parse(access.expiresAt) <= now) return { ready: false, status: '空间连接已失效，请在空间管理同步该空间' };
    return { ready: false, status: '空间信息未同步或已变化，请在空间管理同步该空间' };
  }
  const premium = workspaceSeatSummary(fact).find(item => item.type === 'prolite');
  if (fact?.canManage && premium?.remaining === 0) return { ready: true, status: '高级席位已满' };
  if (fact?.canManage) return { ready: true, status: workspaceSubscriptionState(fact, access, now).label === '账单逾期' ? '当前空间账单逾期，平台拒绝新增邀请' : '可以操作' };
  return { ready: false, status: fact?.motherRole === 'member' ? '当前母号是普通成员，无法管理该空间' : '未获取母号的管理身份，请在空间管理同步该空间' };
}

// Poll and mutation responses have separate fences. A poll begun before a POST
// cannot publish an old success while the POST is in flight or after it fails.
export function createWorkspaceRequestGate() {
  let pollSequence = 0;
  let mutationSequence = 0;
  let verifying = false;
  return {
    beginPoll(): number | null {
      return verifying ? null : ++pollSequence;
    },
    acceptPoll(sequence: number): boolean {
      return !verifying && sequence === pollSequence;
    },
    beginMutation(): number {
      verifying = true;
      pollSequence++;
      return ++mutationSequence;
    },
    isCurrentMutation(sequence: number): boolean {
      return sequence === mutationSequence;
    },
    acceptMutation(sequence: number): boolean {
      if (sequence !== mutationSequence) return false;
      verifying = false;
      return true;
    },
    invalidate(): void {
      pollSequence++;
      mutationSequence++;
      verifying = false;
    },
  };
}
