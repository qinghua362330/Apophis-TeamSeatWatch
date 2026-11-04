import ActionNotice from '../shared/ActionNotice';
import ListPagination from '../shared/ListPagination';
import StatusBadge from '../shared/StatusBadge';
import { formatDateTime } from '../shared/dateTime';
import { Box, Button, Group, Paper, Select, Stack, Table, Text, Textarea, Title } from '@mantine/core';
import { useCallback, useEffect, useState } from 'react';
import OwnerIcon from './OwnerIcon';
import { ownerProblem } from './auth';
import {
  cancelCPARotationCase,
  cpaRotationStatus,
  cpaRotationStatusOptions,
  listCPARotationCases,
  type CPARotationCaseList,
  type CPARotationStatus,
} from './cpaRotation';

type Props = { active?: boolean };

export default function CPARotationView({ active = true }: Props) {
  const [data, setData] = useState<CPARotationCaseList>();
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [status, setStatus] = useState<CPARotationStatus>();
  const [reason, setReason] = useState('');
  const [loading, setLoading] = useState(false);
  const [pending, setPending] = useState<string>();
  const [notice, setNotice] = useState('');
  const [tone, setTone] = useState<'error' | 'success'>('error');

  const load = useCallback(async (signal?: AbortSignal) => {
    setLoading(true);
    try { setData(await listCPARotationCases(page, pageSize, status, signal)); }
    catch (error: unknown) { if (!signal?.aborted) { setTone('error'); setNotice(ownerProblem(error).status === 401 ? '登录已失效，请重新登录。' : '轮换记录读取失败，请刷新重试。'); } }
    finally { if (!signal?.aborted) setLoading(false); }
  }, [page, pageSize, status]);

  useEffect(() => {
    if (!active) return;
    const controller = new AbortController();
    void load(controller.signal);
    return () => controller.abort();
  }, [active, load]);

  async function cancel(caseId: string) {
    const trimmed = reason.trim();
    if (!trimmed) { setTone('error'); setNotice('请填写取消原因。'); return; }
    setPending(caseId); setNotice('');
    try {
      await cancelCPARotationCase(caseId, trimmed);
      setTone('success');
      setNotice('已取消，该案例不会再执行远端操作。');
      await load();
    } catch (error: unknown) {
      setTone('error');
      const code = ownerProblem(error).status;
      setNotice(code === 409 ? '该案例已开始执行或已结束，无法取消。' : '操作失败，请稍后重试。');
    } finally { setPending(undefined); }
  }

  const items = data?.items ?? [];
  return <section aria-labelledby="cpa-rotation-heading" className="management-page">
    <Stack gap={24}>
      <Group className="management-subheader" justify="space-between" align="center">
        <Group gap={12}><Box className="management-page-icon"><OwnerIcon name="degradation" size={20} /></Box><div><Title id="cpa-rotation-heading" order={2}>凭证自动轮换</Title><Text size="sm" c="dimmed">收到有效降级回调后，自动隔离凭证、移除成员、备用号补位并将新凭证注册到 CPA。证据或备用号不足时等待重试。</Text></div></Group>
        <Button variant="default" leftSection={<OwnerIcon name="refresh" size={16} />} loading={loading} onClick={() => void load()}>刷新</Button>
      </Group>
      <ActionNotice message={notice} tone={tone} onClose={() => setNotice('')} />
      <Paper withBorder radius={12} className="management-list-panel">
        <Group className="management-toolbar" justify="space-between" align="flex-end" wrap="wrap">
          <Select aria-label="案例状态" placeholder="全部状态" clearable value={status ?? null} data={cpaRotationStatusOptions} onChange={(value) => { setStatus((value || undefined) as CPARotationStatus | undefined); setPage(1); }} />
          <Textarea aria-label="取消原因" placeholder="取消原因（写入审计）" autosize minRows={1} maxRows={3} w={420} maxLength={500} value={reason} onChange={(event) => setReason(event.currentTarget.value)} />
        </Group>
        <Table.ScrollContainer minWidth={1180}><Table className="management-table" aria-busy={loading}><Table.Thead><Table.Tr><Table.Th>创建时间</Table.Th><Table.Th>阶段</Table.Th><Table.Th>凭证</Table.Th><Table.Th>尝试</Table.Th><Table.Th>下次重试</Table.Th><Table.Th>原因码</Table.Th><Table.Th>操作</Table.Th></Table.Tr></Table.Thead><Table.Tbody>
          {items.map((item) => {
            const display = cpaRotationStatus(item.status);
            const busy = pending === item.id;
            const cancellable = item.status === 'pending_automation' || item.status === 'waiting_evidence';
            const showNext = item.status !== 'completed' && item.status !== 'dismissed';
            return <Table.Tr key={item.id}>
              <Table.Td><Text size="xs">{formatDateTime(item.createdAt)}</Text></Table.Td>
              <Table.Td><StatusBadge {...display} /></Table.Td>
              <Table.Td><Text size="xs" ff="monospace">{item.credentialId}</Text></Table.Td>
              <Table.Td><Text size="sm">{item.attemptCount}</Text></Table.Td>
              <Table.Td><Text size="xs" c="dimmed">{showNext ? formatDateTime(item.nextAttemptAt) : '—'}</Text></Table.Td>
              <Table.Td><Text size="xs" c="dimmed">{item.lastErrorCode ?? '—'}</Text></Table.Td>
              <Table.Td><Group gap={4} justify="center">
                <Button size="xs" variant="subtle" color="gray" disabled={busy || !cancellable} onClick={() => void cancel(item.id)}>取消</Button>
              </Group></Table.Td>
            </Table.Tr>;
          })}
        </Table.Tbody></Table></Table.ScrollContainer>
        {loading ? <Text className="management-empty-state" role="status">正在读取轮换案例</Text> : !items.length ? <Text className="management-empty-state" c="dimmed">暂无轮换案例</Text> : null}
        <ListPagination page={page} pageSize={pageSize} total={data?.total ?? 0} disabled={loading} onPageChange={setPage} onPageSizeChange={(value) => { setPageSize(value); setPage(1); }} />
      </Paper>
    </Stack>
  </section>;
}
