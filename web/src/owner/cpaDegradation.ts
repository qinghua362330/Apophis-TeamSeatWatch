import createClient from 'openapi-fetch';
import type { components, paths } from '../generated/owner';
import { mutationHeaders, OwnerApiError } from './auth';

const api = createClient<paths>({ baseUrl: '', credentials: 'include' });

export type CPADegradationEvent = components['schemas']['CPADegradationEvent'];
export type CPADegradationEventList = components['schemas']['CPADegradationEventList'];
export type CPADegradationStatus = components['schemas']['CPADegradationMappingStatus'];

function result<T>(response: { data?: T; error?: unknown; response: Response }): T {
  if (response.error || response.data === undefined) throw new OwnerApiError(response.response.status, response.error);
  return response.data;
}

export async function listCPADegradationEvents(page = 1, pageSize = 20, status?: CPADegradationStatus, signal?: AbortSignal): Promise<CPADegradationEventList> {
  return result(await api.GET('/api/owner/v1/cpa/degradation-events', {
    params: { query: { page, page_size: pageSize, ...(status ? { status } : {}) } },
    ...(signal ? { signal } : {}),
  }));
}

export async function retryMapCPADegradationEvent(eventId: string): Promise<CPADegradationEvent> {
  return result(await api.POST('/api/owner/v1/cpa/degradation-events/{eventId}/retry-map', {
    params: { path: { eventId }, header: await mutationHeaders() },
  }));
}

export async function dismissCPADegradationEvent(eventId: string): Promise<CPADegradationEvent> {
  return result(await api.POST('/api/owner/v1/cpa/degradation-events/{eventId}/dismiss', {
    params: { path: { eventId }, header: await mutationHeaders() },
  }));
}

export const cpaDegradationStatusOptions: { value: CPADegradationStatus; label: string }[] = [
  { value: 'pending_rotation', label: '待人工轮转' },
  { value: 'not_found', label: '未匹配席位' },
  { value: 'ambiguous', label: '匹配不唯一' },
  { value: 'dismissed', label: '已忽略' },
];

export function cpaDegradationStatus(status: CPADegradationStatus): { label: string; tone: 'gray' | 'indigo' | 'success' | 'warning' | 'error' } {
  switch (status) {
    case 'pending_rotation': return { label: '待人工轮转', tone: 'warning' };
    case 'not_found': return { label: '未匹配席位', tone: 'error' };
    case 'ambiguous': return { label: '匹配不唯一', tone: 'error' };
    case 'dismissed': return { label: '已忽略', tone: 'gray' };
    case 'mapped': return { label: '已映射', tone: 'success' };
    default: return { label: '待映射', tone: 'indigo' };
  }
}
