import ActionNotice from '../shared/ActionNotice';
import ListPagination from '../shared/ListPagination';
import StatusBadge from '../shared/StatusBadge';
import { formatDateTime } from '../shared/dateTime';
import { Box, Button, Group, Paper, Select, Stack, Table, Text, Title } from '@mantine/core';
import { useCallback, useEffect, useState } from 'react';
import OwnerIcon from './OwnerIcon';
import { ownerProblem } from './auth';
import {
  cpaDegradationStatus,
  cpaDegradationStatusOptions,
  dismissCPADegradationEvent,
  listCPADegradationEvents,
  retryMapCPADegradationEvent,
  type CPADegradationEventList,
  type CPADegradationStatus,
} from './cpaDegradation';

type Props = { active?: boolean };

export default function CPADegradationView({ active = true }: Props) {
  const [data, setData] = useState<CPADegradationEventList>();
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [status, setStatus] = useState<CPADegradationStatus>();
  const [loading, setLoading] = useState(false);
  const [pending, setPending] = useState<string>();
  const [notice, setNotice] = useState('');

  const load = useCallback(async (signal?: AbortSignal) => {
    setLoading(true); setNotice('');
    try { setData(await listCPADegradationEvents(page, pageSize, status, signal)); }
    catch (error: unknown) { if (!signal?.aborted) setNotice(ownerProblem(error).status === 401 ? '登录已失效，请重新登录。' : '降智事件读取失败，请刷新重试。'); }
    finally { if (!signal?.aborted) setLoading(false); }
  }, [page, pageSize, status]);

  useEffect(() => {
    if (!active) return;
    const controller = new AbortController();
    void load(controller.signal);
    return () => controller.abort();
  }, [active, load]);

  async function mutate(eventId: string, action: 'retry' | 'dismiss') {
    setPending(`${action}:${eventId}`); setNotice('');
    try {
      if (action === 'retry') await retryMapCPADegradationEvent(eventId);
      else await dismissCPADegradationEvent(eventId);
      await load();
    } catch (error: unknown) {
      setNotice(ownerProblem(error).status === 409 ? '该事件当前状态不允许此操作。' : '操作失败，请稍后重试。');
    } finally { setPending(undefined); }
  }

  const items = data?.items ?? [];
  return <section aria-labelledby="cpa-degradation-heading" className="management-page">
    <Stack gap={24}>
      <Group className="management-subheader" justify="space-between" align="center">
        <Group gap={12}><Box className="management-page-icon"><OwnerIcon name="degradation" size={20} /></Box><div><Title id="cpa-degradation-heading" order={2}>降智事件</Title><Text size="sm" c="dimmed">仅审核 CPA 已隔离的凭证；本页不会自动踢席位或邀请新成员。</Text></div></Group>
        <Button variant="default" leftSection={<OwnerIcon name="refresh" size={16} />} loading={loading} onClick={() => void load()}>刷新</Button>
      </Group>
      <ActionNotice message={notice} onClose={() => setNotice('')} />
      <Paper withBorder radius={12} className="management-list-panel">
        <Group className="management-toolbar" justify="space-between">
          <Select aria-label="映射状态" placeholder="全部状态" clearable value={status ?? null} data={cpaDegradationStatusOptions} onChange={(value) => { setStatus((value || undefined) as CPADegradationStatus | undefined); setPage(1); }} />
          <Text size="sm" c="dimmed">事件只包含凭证标识、邮箱、模型判断和时间，不包含 Token、Prompt 或图片。</Text>
        </Group>
        <Table.ScrollContainer minWidth={1180}><Table className="management-table" aria-busy={loading}><Table.Thead><Table.Tr><Table.Th>检测时间</Table.Th><Table.Th>账号</Table.Th><Table.Th>凭证</Table.Th><Table.Th>期望 / 检测</Table.Th><Table.Th>置信度</Table.Th><Table.Th>映射状态</Table.Th><Table.Th>映射说明</Table.Th><Table.Th>操作</Table.Th></Table.Tr></Table.Thead><Table.Tbody>
          {items.map((event) => { const display = cpaDegradationStatus(event.mappingStatus); const busy = pending?.endsWith(event.id); return <Table.Tr key={event.id}><Table.Td><Text size="xs">{formatDateTime(event.observedAt)}</Text></Table.Td><Table.Td><Text size="sm">{event.email}</Text></Table.Td><Table.Td><Text size="xs" ff="monospace">{event.credentialId}</Text></Table.Td><Table.Td><Text size="sm">{event.expectedModel}</Text><Text size="xs" c="dimmed">{event.detectedModel}</Text></Table.Td><Table.Td>{Math.round(event.confidence * 100)}%</Table.Td><Table.Td><StatusBadge {...display} /></Table.Td><Table.Td><Text size="xs" c="dimmed">{event.mappingMessage}</Text></Table.Td><Table.Td><Group gap={4} justify="center"><Button size="xs" variant="subtle" disabled={busy || event.mappingStatus === 'dismissed'} onClick={() => void mutate(event.id, 'retry')}>重新映射</Button><Button size="xs" variant="subtle" color="gray" disabled={busy || event.mappingStatus === 'dismissed'} onClick={() => void mutate(event.id, 'dismiss')}>忽略</Button></Group></Table.Td></Table.Tr>; })}
        </Table.Tbody></Table></Table.ScrollContainer>
        {loading ? <Text className="management-empty-state" role="status">正在读取降智事件</Text> : !items.length ? <Text className="management-empty-state" c="dimmed">暂无降智事件</Text> : null}
        <ListPagination page={page} pageSize={pageSize} total={data?.total ?? 0} disabled={loading} onPageChange={setPage} onPageSizeChange={(value) => { setPageSize(value); setPage(1); }} />
      </Paper>
    </Stack>
  </section>;
}
