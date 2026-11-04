import ActionNotice from '../shared/ActionNotice';
import { useActionFeedback } from '../shared/useActionFeedback';
import BrandIdentity from '../shared/BrandIdentity';
import { usePageTitle } from '../shared/usePageTitle';
import {
  ActionIcon,
  Badge,
  Box,
  Button,
  Card,
  Divider,
  Group,
  Loader,
  MantineProvider,
  NavLink,
  Paper,
  PasswordInput,
  Stack,
  Switch,
  Text,
  TextInput,
  Title,
  useMantineColorScheme,
  useComputedColorScheme,
} from '@mantine/core';
import { useEffect, useState, type ChangeEvent, type SubmitEvent } from 'react';
import type { components } from '../generated/owner';
import {
  clearCsrf,
  getAuthStatus,
  loginOwner,
  logoutOwner,
  ownerProblem,
} from './auth';
import { appTheme } from '../shared/theme';
import ChildMaterialsView from './ChildMaterialsView';
import WorkspaceDiscoveryView from './WorkspaceDiscoveryView';
import StandbyChildBatchesView from './StandbyChildBatchesView';
import OperationWizard from './OperationWizard';
import type { OperationStartContext } from './batchOperations';
import { accountsAcceptance, locationTitle, ownerLocation, ownerPages, parentPage, type OwnerLocation } from './navigation';
import DeliveryRecordsView from './DeliveryRecordsView';
import type { RedemptionFocus } from './redemptionRecords';
import CardManagementView from './CardManagementView';
import RotationManagementView from './RotationManagementView';
import CPADegradationView from './CPADegradationView';
import ProxyManagementView from './ProxyManagementView';
import OwnerIcon from './OwnerIcon';
import LoginDotGrid from './LoginDotGrid';
import {
  destinationApi,
  type Destination,
  type DestinationError,
  type TestOutcome,
} from './deliveryDestination';

type AuthStatus = components['schemas']['AuthStatus'];
type AuthState =
  | { kind: 'loading' }
  | { kind: 'signed-out'; notice?: string }
  | { kind: 'signed-in'; status: AuthStatus };

type LoginFields = {
  username: string;
  password: string;
};

const initialFields: LoginFields = { username: '', password: '' };

function ThemeToggle() {
  const { toggleColorScheme } = useMantineColorScheme();
  const colorScheme = useComputedColorScheme('light');
  const label = colorScheme === 'dark' ? '浅色模式' : '深色模式';
  return <ActionIcon variant="subtle" color="gray" size={32} aria-label={label} title={label} onClick={() => toggleColorScheme()}>
    <OwnerIcon name={colorScheme === 'dark' ? 'sun' : 'moon'} size={18} />
  </ActionIcon>;
}

export default function OwnerApp() {
  const [auth, setAuth] = useState<AuthState>({ kind: 'loading' });

  useEffect(() => {
    let active = true;
    void getAuthStatus()
      .then((status) => {
        if (active) setAuth({ kind: 'signed-in', status });
      })
      .catch((error: unknown) => {
        if (!active) return;
        const problem = ownerProblem(error);
        if (problem.status === 401) {
          setAuth({ kind: 'signed-out' });
        } else {
          setAuth({
            kind: 'signed-out',
            notice: '登录服务暂不可用',
          });
        }
      });

    return () => {
      active = false;
    };
  }, []);

  if (auth.kind === 'loading') {
    return (
      <MantineProvider theme={appTheme} defaultColorScheme="auto">
        <div className="auth-loading" role="status" aria-label="正在确认登录状态">
          <Loader color="indigo" size="sm" />
        </div>
      </MantineProvider>
    );
  }

  return (
    <MantineProvider theme={appTheme} defaultColorScheme="auto">
      {auth.kind === 'signed-in' ? (
        <SignedInView
          onSignedOut={() => setAuth({ kind: 'signed-out' })}
        />
      ) : (
        <LoginView
          initialNotice={auth.notice}
          onSignedIn={(status) => setAuth({ kind: 'signed-in', status })}
        />
      )}
    </MantineProvider>
  );
}

function LoginView({
  initialNotice,
  onSignedIn,
}: {
  initialNotice: string | undefined;
  onSignedIn: (status: AuthStatus) => void;
}) {
  const [fields, setFields] = useState(initialFields);
  const [notice, setNotice, dismissNotice] = useActionFeedback('', initialNotice ?? '');
  const [pending, setPending] = useState(false);
  usePageTitle('管理登录');

  async function submit(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!fields.username.trim() || !fields.password) {
      setNotice('请输入用户名和密码');
      return;
    }

    setNotice('');
    setPending(true);
    try {
      await loginOwner({
        username: fields.username,
        password: fields.password,
      });
      const status = await getAuthStatus();
      onSignedIn(status);
    } catch (error: unknown) {
      const problem = ownerProblem(error);
      if (problem.code === 'csrf_rejected') clearCsrf();
      if (problem.status === 429) {
        setNotice(`尝试次数过多，请在 ${problem.retryAfterSeconds ?? 900} 秒后重试。`);
      } else if (problem.status === undefined || problem.status === 403 || problem.status >= 500) {
        setNotice('登录服务暂不可用');
      } else {
        setNotice('用户名或密码不正确');
      }
    } finally {
      setPending(false);
    }
  }

  return (
    <main className="auth-page">
      <Box component="section" className="auth-brand-panel" aria-label="TeamSeatWatch">
        <BrandIdentity inverse />
        <Box className="auth-brand-display">
          <Text className="auth-brand-eyebrow">APOPHIS</Text>
          <Title order={2} className="auth-wordmark brand-rainbow-text">TeamSeat<br />Watch.</Title>
        </Box>
        <LoginDotGrid />
      </Box>
      <Box component="section" className="auth-form-panel">
        <Box className="auth-utilities"><ThemeToggle /></Box>
        <Box className="auth-card">
          <Box className="auth-mobile-brand"><BrandIdentity /></Box>
          <Box className="auth-form-heading">
            <Text className="auth-overline">管理控制台</Text>
            <Title className="auth-title" order={1}>登录</Title>
          </Box>
          {notice ? (
            <ActionNotice message={notice} onClose={dismissNotice} title="无法登录" mt="lg" />
          ) : null}

          <form className="auth-form" onSubmit={submit} noValidate>
            <Stack gap="lg">
              <TextInput
                label="用户名"
                placeholder="输入用户名"
                radius={6}
                autoComplete="username"
                autoFocus
                maxLength={254}
                required
                withAsterisk={false}
                value={fields.username}
                onChange={(event: ChangeEvent<HTMLInputElement>) => setFields({ ...fields, username: event.currentTarget.value })}
              />
              <PasswordInput
                label="密码"
                placeholder="输入密码"
                radius={6}
                autoComplete="current-password"
                maxLength={1024}
                required
                withAsterisk={false}
                value={fields.password}
                onChange={(event: ChangeEvent<HTMLInputElement>) => setFields({ ...fields, password: event.currentTarget.value })}
              />
              <Button type="submit" loading={pending} fullWidth size="md" radius={6} rightSection={<OwnerIcon name="arrow-right" size={16} />}>
                登录
              </Button>
            </Stack>
          </form>

        </Box>
      </Box>
    </main>
  );
}

function SignedInView({
  onSignedOut,
}: {
  onSignedOut: () => void;
}) {
  const [pendingAction, setPendingAction] = useState<'logout' | null>(null);
  const [message, setMessage, dismissMessage] = useActionFeedback('');
  const [location, setLocation] = useState(() => ownerLocation(window.location.hash));
  usePageTitle(locationTitle(location));
  const [visited, setVisited] = useState<Set<OwnerLocation>>(() => new Set([ownerLocation(window.location.hash)]));
  const [repairLocation, setRepairLocation] = useState<OwnerLocation | null>(null);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => localStorage.getItem('owner-sidebar-collapsed') === 'true');
  const [redemptionFocus, setRedemptionFocus] = useState<RedemptionFocus | null>(null);
  const [operationCardsBatch, setOperationCardsBatch] = useState<string | null>(null);
  const [operationRotationBatch, setOperationRotationBatch] = useState<string | null>(null);
  const [startNextBatch, setStartNextBatch] = useState<OperationStartContext | null>(null);

  function toggleSidebar() {
    const next = !sidebarCollapsed;
    setSidebarCollapsed(next);
    localStorage.setItem('owner-sidebar-collapsed', String(next));
  }

  function navigate(next: OwnerLocation) {
    setLocation(next);
    setVisited((current) => new Set(current).add(next));
    window.location.hash = next;
  }

  useEffect(() => {
    const change = () => {
      const next = ownerLocation(window.location.hash);
      setLocation(next);
      setVisited((current) => new Set(current).add(next));
    };
    window.addEventListener('hashchange', change);
    return () => window.removeEventListener('hashchange', change);
  }, []);

  useEffect(() => {
    let active = true;
    const revalidate = async () => {
      try {
        await getAuthStatus();
      } catch (error: unknown) {
        if (active && ownerProblem(error).status === 401) {
          clearCsrf();
          onSignedOut();
        }
      }
    };
    const interval = window.setInterval(() => void revalidate(), 60_000);
    const onVisibilityChange = () => {
      if (document.visibilityState === 'visible') void revalidate();
    };
    document.addEventListener('visibilitychange', onVisibilityChange);
    return () => {
      active = false;
      window.clearInterval(interval);
      document.removeEventListener('visibilitychange', onVisibilityChange);
    };
  }, [onSignedOut]);

  async function logout() {
    setPendingAction('logout');
    setMessage('');
    try {
      await logoutOwner();
      clearCsrf();
      onSignedOut();
    } catch (error: unknown) {
      const problem = ownerProblem(error);
      if (problem.status === 401) {
        clearCsrf();
        onSignedOut();
      } else {
        setMessage('退出失败，请稍后重试。');
      }
    } finally {
      setPendingAction(null);
    }
  }

  return (
    <Box className="owner-shell" data-sidebar-collapsed={sidebarCollapsed || undefined}>
      <Box component="aside" className="owner-sidebar">
        <Box className="owner-brand"><BrandIdentity /></Box>
        <Box component="nav" id="owner-navigation" aria-label="管理菜单" className="owner-navigation">
          {ownerPages.map((page) => <NavLink
            key={page.id} component="a" href={accountsAcceptance && page.id !== 'accounts' ? undefined : `#${page.id}`} label={page.label}
            disabled={accountsAcceptance && page.id !== 'accounts'}
            aria-label={page.label} title={sidebarCollapsed ? page.label : undefined}
            leftSection={<OwnerIcon name={page.id} size={18} />}
            active={parentPage(location) === page.id} aria-current={parentPage(location) === page.id ? 'page' : undefined}
            onClick={(event) => { if (accountsAcceptance && page.id !== 'accounts') { event.preventDefault(); return; } if (page.id === 'cards') setOperationCardsBatch(null); if (page.id === 'redemptions') setRedemptionFocus(null); if (page.id === 'rotation') setOperationRotationBatch(null); navigate(page.id); }}
          />)}
        </Box>
        <Stack gap="xs" className="owner-sidebar-footer">
          <Divider />
          {sidebarCollapsed ? <ActionIcon variant="subtle" color="gray" size={44} aria-label="退出登录" title="退出登录" onClick={logout} loading={pendingAction === 'logout'}><OwnerIcon name="logout" size={18} /></ActionIcon> : <Button variant="subtle" color="gray" size="xs" leftSection={<OwnerIcon name="logout" size={16} />} onClick={logout} loading={pendingAction === 'logout'}>退出登录</Button>}
        </Stack>
      </Box>
      <Box className="owner-workspace">
        <Box component="header" className="owner-topbar">
          <Group gap={12}><ActionIcon variant="subtle" color="gray" size={32} aria-label={sidebarCollapsed ? '展开菜单' : '收起菜单'} title={sidebarCollapsed ? '展开菜单' : '收起菜单'} aria-expanded={!sidebarCollapsed} aria-controls="owner-navigation" onClick={toggleSidebar}><OwnerIcon name={sidebarCollapsed ? 'sidebar-expand' : 'sidebar-collapse'} size={18} /></ActionIcon><Group gap={12} className="owner-breadcrumb"><Text size="sm" c="dimmed">管理控制台</Text><OwnerIcon name="arrow-right" size={12} /><Text size="sm">{locationTitle(location)}</Text></Group></Group>
          <ThemeToggle />
        </Box>
        <Box component="main" className="owner-main">
        <Box className="owner-content">
          <ActionNotice message={message} onClose={dismissMessage} mb="md" />
          {repairLocation && location !== repairLocation ? <Group mb="md"><Button variant="default" onClick={() => { navigate(repairLocation); setRepairLocation(null); }}>返回{locationTitle(repairLocation)}</Button></Group> : null}
          {visited.has('accounts') ? <Box hidden={location !== 'accounts'}><ChildMaterialsView active={location === 'accounts'} /></Box> : null}
          {visited.has('workspaces') ? <Box hidden={location !== 'workspaces'}><WorkspaceDiscoveryView active={location === 'workspaces'} onNextAction={(motherAccountId, workspaceId) => { if (repairLocation) navigate(repairLocation); else { setStartNextBatch((value) => ({ requestId: (value?.requestId ?? 0) + 1, motherAccountId, workspaceId })); navigate('operation'); } }} /></Box> : null}
          {visited.has('batches') ? <Box hidden={location !== 'batches'}><StandbyChildBatchesView active={location === 'batches'} /></Box> : null}
          {visited.has('operation') ? <Box hidden={location !== 'operation'}><OperationWizard active={location === 'operation'} startNextBatch={startNextBatch} onOpenCards={(id) => { setOperationCardsBatch(id); navigate('cards'); }} onOpenRotation={(id) => { setOperationRotationBatch(id); navigate('rotation'); }} onRepair={(tab) => {
            const target: OwnerLocation = tab === 'standby' ? 'batches' : 'workspaces';
            setRepairLocation('operation'); navigate(target);
          }} /></Box> : null}
          {visited.has('cards') ? <Box hidden={location !== 'cards'}><CardManagementView onClearBatchScope={() => setOperationCardsBatch(null)} focusBatchId={operationCardsBatch} active={location === 'cards'} onRecords={(record) => { setRedemptionFocus((value) => ({ membershipId: record.membershipId, motherAccountId: record.motherAccountId, workspaceId: record.workspaceId, batchId: record.batchId, requestId: (value?.requestId ?? 0) + 1 })); navigate('redemptions'); }} onChannelSettings={() => navigate('channel-settings')} /></Box> : null}
          {visited.has('redemptions') ? <Box hidden={location !== 'redemptions'}><DeliveryRecordsView active={location === 'redemptions'} focus={redemptionFocus} onClearFocus={() => setRedemptionFocus(null)} onBackToCards={() => navigate('cards')} /></Box> : null}
          {visited.has('rotation') ? <Box hidden={location !== 'rotation'}><RotationManagementView onClearBatchScope={() => setOperationRotationBatch(null)} focusBatchId={operationRotationBatch} active={location === 'rotation'} onStartNextBatch={(context) => { setStartNextBatch((value) => ({ requestId: (value?.requestId ?? 0) + 1, ...context })); navigate('operation'); }} /></Box> : null}
          {visited.has('degradation') ? <Box hidden={location !== 'degradation'}><CPADegradationView active={location === 'degradation'} /></Box> : null}
          {visited.has('proxy') ? <Box hidden={location !== 'proxy'}><ProxyManagementView active={location === 'proxy'} /></Box> : null}
          {visited.has('channel-settings') ? <Box hidden={location !== 'channel-settings'}><DeliveryDestinationPanel onBack={() => navigate('cards')} /></Box> : null}
        </Box>
        </Box>
      </Box>
    </Box>
  );
}

type DestinationForm = { name: string; endpoint: string; targetGroup: string; secret: string };
const blankDestinationForm: DestinationForm = { name: '', endpoint: '', targetGroup: '', secret: '' };

function destinationErrorMessage(error: unknown): string {
  const code = (error as Partial<DestinationError>).code;
  switch (code) {
    case 'session_expired': return 'Owner 会话已过期，请重新登录。';
    case 'csrf_rejected': return '安全校验失败，请刷新页面后重试。';
    case 'invalid_destination': return '去向资料不完整或格式不正确';
    case 'destination_not_found': return '该交付去向已不存在，请刷新列表。';
    case 'destination_not_selectable': return '去向待启用或测试';
    case 'destination_disabled': return '请先启用去向，再测试连接与目标组。';
    case 'test_stale': return '测试完成前配置已变化，请重新测试当前配置。';
    default: return '操作未完成，请稍后重试。';
  }
}

function outcomeLabel(outcome: TestOutcome): { label: string; color: 'gray' | 'green' | 'red' | 'yellow' } {
  switch (outcome) {
    case 'connected': return { label: '通过', color: 'green' };
    case 'connection_failed': return { label: '连接失败：检查地址或网络', color: 'red' };
    case 'permission_denied': return { label: '权限不足：检查去向授权', color: 'red' };
    case 'target_mismatch': return { label: '目标组不匹配：检查目标范围', color: 'yellow' };
    default: return { label: '未测试', color: 'gray' };
  }
}

function DestinationTestSummary({ destination }: { destination: Destination }) {
  const connection = outcomeLabel(destination.test?.connection ?? 'untested');
  const target = outcomeLabel(destination.test?.target ?? 'untested');
  return (
    <Stack gap={4} mt="sm">
      <Group gap="xs"><Text size="sm" c="dimmed">连接</Text><Badge color={connection.color} variant="light">{connection.label}</Badge></Group>
      <Group gap="xs"><Text size="sm" c="dimmed">目标组</Text><Badge color={target.color} variant="light">{target.label}</Badge></Group>
    </Stack>
  );
}

function DeliveryDestinationPanel({ onBack }: { onBack: () => void }) {
  const [destinations, setDestinations] = useState<Destination[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [form, setForm] = useState<DestinationForm>(blankDestinationForm);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [wizardOpen, setWizardOpen] = useState(false);
  const [notice, setNotice, dismissNotice] = useActionFeedback('');
  const [pending, setPending] = useState<string | null>(null);

  const sync = async () => {
    const items = await destinationApi.list();
    setDestinations(items);
    setSelectedId(items.find((item) => item.selected)?.id ?? null);
  };
  useEffect(() => { void sync().catch((error: unknown) => setNotice(destinationErrorMessage(error))); }, []);
  const performAction = async (key: string, action: () => unknown | Promise<unknown>) => {
    setPending(key); setNotice('');
    try { await action(); await sync(); } catch (error: unknown) { setNotice(destinationErrorMessage(error)); } finally { setPending(null); }
  };
  const submit = (event: SubmitEvent<HTMLFormElement>) => {
    event.preventDefault();
    void performAction('save', () => {
      const operation = editingId
        ? destinationApi.update(editingId, form, destinations.find((destination) => destination.id === editingId)?.enabled ?? true)
        : destinationApi.create(form);
      return operation.then(() => {
        setForm(blankDestinationForm); setEditingId(null); setWizardOpen(false);
      });
    });
  };
  const startEdit = (destination: Destination) => {
    setEditingId(destination.id);
    setForm({ name: destination.name, endpoint: destination.endpoint, targetGroup: destination.targetGroup, secret: '' });
    setWizardOpen(false); setNotice('');
  };
  const cancelEdit = () => { setEditingId(null); setForm(blankDestinationForm); setWizardOpen(false); };

  return (
    <section aria-labelledby="destination-heading" className="management-page destination-page">
      <Group className="management-subheader" justify="space-between" align="center">
        <Group gap={12}><Box className="management-page-icon"><OwnerIcon name="cards" size={20} /></Box><Title id="destination-heading" order={2}>渠道设置</Title></Group>
        <Group gap={8}><Button variant="default" leftSection={<OwnerIcon name="arrow-left" size={16} />} onClick={onBack}>返回卡密管理</Button>{!destinations.length ? <Button onClick={() => setWizardOpen(true)}>开始配置</Button> : <Button variant="default" onClick={() => { setWizardOpen(true); setEditingId(null); setForm(blankDestinationForm); }}>添加去向</Button>}</Group>
      </Group>
      <ActionNotice message={notice} onClose={dismissNotice} mb="lg" title="操作未完成" />

      {!destinations.length && !wizardOpen ? (
        <Paper withBorder radius={12} p={{ base: 'lg', sm: 'xl' }}>
          <Stack gap="sm"><Title order={3} size="h4">还没有可用的交付去向</Title><Group><Button radius={6} onClick={() => setWizardOpen(true)}>进入配置向导</Button></Group></Stack>
        </Paper>
      ) : null}

      {wizardOpen ? (
        <Paper withBorder radius={12} p={{ base: 'lg', sm: 'xl' }} mb="lg">
          <form onSubmit={submit} noValidate>
            <Stack gap="md">
              <div><Title order={3} size="h4">{editingId ? '修改交付去向' : '配置交付去向'}</Title></div>
              <TextInput label="名称" required value={form.name} onChange={(event) => setForm({ ...form, name: event.currentTarget.value })} />
              <TextInput label="渠道地址" placeholder="https://hub.example.test/api/v1" required value={form.endpoint} onChange={(event) => setForm({ ...form, endpoint: event.currentTarget.value })} />
              <TextInput label="目标组 ID" placeholder="例如：42" required value={form.targetGroup} onChange={(event) => setForm({ ...form, targetGroup: event.currentTarget.value })} />
              <PasswordInput label={editingId ? '连接密钥（留空保留）' : '连接密钥'} required={!editingId} autoComplete="new-password" value={form.secret} onChange={(event) => setForm({ ...form, secret: event.currentTarget.value })} />
              <Group justify="flex-end"><Button type="button" variant="default" radius={6} onClick={cancelEdit}>返回</Button><Button type="submit" radius={6} loading={pending === 'save'}>{editingId ? '保存修改' : '保存配置'}</Button></Group>
            </Stack>
          </form>
        </Paper>
      ) : null}

      <Stack gap="md">
        {destinations.map((destination) => (
          <Card key={destination.id} withBorder radius={12} padding="lg">
            <Group justify="space-between" align="flex-start" wrap="nowrap">
              <div><Title order={3} size="h4">{destination.name}</Title><Text size="sm" c="dimmed" mt={4}>{destination.endpoint}</Text><Text size="sm" c="dimmed">目标组 ID：{destination.targetGroup}</Text></div>
              <Badge color={destination.enabled ? 'green' : 'gray'} variant="light">{destination.enabled ? '已启用' : '已停用'}</Badge>
            </Group>
            <DestinationTestSummary destination={destination} />
            <Divider my="md" />
            <Group justify="space-between" align="center">
              <Switch label={destination.enabled ? '启用' : '停用'} checked={destination.enabled} onChange={(event) => void performAction(`toggle:${destination.id}`, () => destinationApi.setEnabled(destination.id, event.currentTarget.checked))} disabled={pending !== null} />
              <Group gap="xs"><Button variant="subtle" radius={6} onClick={() => startEdit(destination)} disabled={pending !== null}>修改</Button><Button variant="light" radius={6} onClick={() => void performAction(`test:${destination.id}`, () => destinationApi.test(destination.id))} loading={pending === `test:${destination.id}`} disabled={pending !== null || !destination.enabled}>测试连接与目标组</Button><Button variant="light" radius={6} onClick={() => void performAction(`select:${destination.id}`, () => destinationApi.select(destination.id))} disabled={pending !== null || !destination.enabled || destination.test?.connection !== 'connected' || destination.test?.target !== 'connected'}>{selectedId === destination.id ? '当前已选择' : '选择去向'}</Button></Group>
            </Group>
          </Card>
        ))}
      </Stack>
    </section>
  );
}
