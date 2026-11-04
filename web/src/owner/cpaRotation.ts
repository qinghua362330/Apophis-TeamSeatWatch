import createClient from 'openapi-fetch';
import type { components, paths } from '../generated/owner';
import { mutationHeaders, OwnerApiError } from './auth';

const api = createClient<paths>({ baseUrl: '', credentials: 'include' });

export type CPARotationCase = components['schemas']['CPARotationCase'];
export type CPARotationCaseList = components['schemas']['CPARotationCaseList'];
export type CPARotationStatus = components['schemas']['CPARotationCaseStatus'];

function result<T>(response: { data?: T; error?: unknown; response: Response }): T {
  if (response.error || response.data === undefined) throw new OwnerApiError(response.response.status, response.error);
  return response.data;
}

export async function listCPARotationCases(page = 1, pageSize = 20, status?: CPARotationStatus, signal?: AbortSignal): Promise<CPARotationCaseList> {
  return result(await api.GET('/api/owner/v1/cpa/rotation-cases', {
    params: { query: { page, page_size: pageSize, ...(status ? { status } : {}) } },
    ...(signal ? { signal } : {}),
  }));
}

export async function cancelCPARotationCase(caseId: string, reason: string): Promise<CPARotationCase> {
  return result(await api.POST('/api/owner/v1/cpa/rotation-cases/{caseId}/cancel', {
    params: { path: { caseId }, header: await mutationHeaders() },
    body: { reason },
  }));
}

const statusLabels: Record<string, string> = {
  pending_automation: '等待执行',
  waiting_evidence: '等待成员证据',
  quarantining: '正在隔离凭证',
  removal_queued: '已排入移除',
  removal_running: '正在移除成员',
  removal_verified: '移除已确认',
  waiting_replacement: '等待备用账号',
  replacement_queued: '已排入补位',
  replacement_running: '正在补位登录',
  credentials_pending: '等待新凭证',
  delivering: '正在注册回 CPA',
  completed: '已完成',
  blocked: '已阻塞',
  failed: '已失败',
  dismissed: '已取消',
};

export function cpaRotationStatus(status: CPARotationStatus): { label: string; tone: 'gray' | 'indigo' | 'success' | 'warning' | 'error' } {
  const label = statusLabels[status] ?? status;
  switch (status) {
    case 'completed': return { label, tone: 'success' };
    case 'blocked':
    case 'failed': return { label, tone: 'error' };
    case 'dismissed': return { label, tone: 'gray' };
    case 'quarantining':
    case 'removal_queued':
    case 'removal_running':
    case 'replacement_queued':
    case 'replacement_running':
    case 'credentials_pending':
    case 'delivering': return { label, tone: 'indigo' };
    default: return { label, tone: 'warning' };
  }
}

export const cpaRotationStatusOptions: { value: CPARotationStatus; label: string }[] = [
  { value: 'pending_automation', label: '等待执行' },
  { value: 'waiting_evidence', label: '等待成员证据' },
  { value: 'completed', label: '已完成' },
  { value: 'blocked', label: '已阻塞' },
  { value: 'dismissed', label: '已取消' },
];

