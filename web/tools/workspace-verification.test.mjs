import test from 'node:test';
import assert from 'node:assert/strict';
import { canShowWorkspaceFacts, canShowSelectedWorkspaceFacts, canShowSelectedWorkspaceReadSource, createWorkspaceRequestGate, selectedWorkspaceOperationState, workspaceSubscriptionState } from '../src/owner/workspaceVerification.ts';
import { workspaceSeatSummary } from '../src/owner/seatTypes.ts';

const fact = {
  status: 'verified', permission: 'read', canManage: false, accessStatus: 'readable',
  completeness: 'complete', expiresAt: '2026-01-08T00:00:00Z', exchangeId: 'exchange-1',
};

test('billing delinquency overrides future expiry and unknown flags never appear healthy', () => {
  const now = Date.parse('2026-01-07T00:00:00Z');
  const access = { status: 'ready', expiresAt: fact.expiresAt, exchangeId: fact.exchangeId };
  const subscription = { ...fact, subscriptionStatus: 'delinquent', activeUntil: '2026-11-07T00:00:00Z', readSources: [{ source: 'subscriptions', observedAt: '2026-01-07T00:00:00Z', completeness: 'complete', permission: 'read', outcome: 'operational' }] };
  assert.deepEqual(workspaceSubscriptionState(subscription, access, now), { label: '账单逾期', tone: 'error', observedAt: subscription.readSources[0].observedAt });
  assert.equal(workspaceSubscriptionState({ ...subscription, status: 'partial', permission: 'unknown', completeness: 'partial' }, access, now).label, '账单逾期');
  assert.equal(workspaceSubscriptionState({ ...subscription, subscriptionStatus: undefined }, access, now).label, '未获取');
  assert.equal(workspaceSubscriptionState({ ...subscription, subscriptionStatus: 'active' }, access, now).label, '有效');
  assert.equal(workspaceSubscriptionState({ ...subscription, subscriptionStatus: 'active', activeUntil: '2026-01-06T00:00:00Z' }, access, now).label, '已到期');
  assert.equal(workspaceSubscriptionState({ ...subscription, subscriptionStatus: 'inactive' }, access, now).label, '未激活');
  for (const status of ['failed', 'stale', 'verifying', 'permission_denied']) assert.equal(workspaceSubscriptionState({ ...subscription, status }, access, now).label, '未同步');
  assert.equal(workspaceSubscriptionState(subscription, { ...access, exchangeId: 'another' }, now).label, '未同步');
  assert.equal(workspaceSubscriptionState(subscription, access, Date.parse(access.expiresAt)).label, '未同步');
  assert.deepEqual(selectedWorkspaceOperationState({ ...subscription, canManage: true }, access, now), { ready: true, status: '当前空间账单逾期，平台拒绝新增邀请' });
});

test('verified facts need current, complete read evidence', () => {
  const now = Date.parse('2026-01-07T00:00:00Z');
  assert.equal(canShowWorkspaceFacts(fact, now), true);
  assert.equal(canShowWorkspaceFacts(fact, Date.parse(fact.expiresAt)), false);
  for (const status of ['pending', 'partial', 'failed', 'permission_denied', 'stale']) {
    assert.equal(canShowWorkspaceFacts({ ...fact, status }, now), false, status);
  }
  assert.equal(canShowWorkspaceFacts({ ...fact, permission: 'read' }, now), true, 'read success proves facts, not write authority');
  assert.equal(canShowWorkspaceFacts({ ...fact, permission: 'manage' }, now), true, 'manage evidence also proves readable facts');
  for (const permission of ['denied', 'unknown']) {
    assert.equal(canShowWorkspaceFacts({ ...fact, permission }, now), false, permission);
  }
  assert.equal(canShowWorkspaceFacts({ ...fact, accessStatus: 'permission_denied' }, now), false);
  assert.equal(canShowWorkspaceFacts({ ...fact, completeness: 'partial' }, now), false);
  assert.equal(canShowWorkspaceFacts({ ...fact, expiresAt: undefined }, now), false);
  assert.equal(canShowWorkspaceFacts(null, now), false);
  assert.equal(canShowWorkspaceFacts({ ...fact, status: 'verifying' }, now), false);
});

test('explicit subscription amounts survive partial roster without granting management', () => {
  const now = Date.parse('2026-01-07T00:00:00Z');
  const access = { status: 'ready', expiresAt: fact.expiresAt, exchangeId: 'exchange-1' };
  const partial = { ...fact, status: 'partial', permission: 'unknown', completeness: 'partial', seatEntitlements: { default: 2, prolite: 9 }, seatTypeCounts: { default: 2, prolite: 99 }, readSources: [{ source: 'subscriptions', completeness: 'complete', permission: 'read', outcome: 'operational' }] };
  assert.equal(canShowSelectedWorkspaceReadSource(partial, access, 'subscriptions', now), true);
  assert.equal(canShowSelectedWorkspaceFacts(partial, access, now), false);
  assert.equal(selectedWorkspaceOperationState(partial, access, now).ready, false);
  const premium = workspaceSeatSummary(partial).find(item => item.type === 'prolite');
  assert.equal(premium.opened, 9);
  assert.equal(premium.members, 99);
  assert.equal(premium.invitations, undefined);
  assert.equal(workspaceSeatSummary({ ...partial, seatEntitlements: { default: 2 } }).find(item => item.type === 'prolite').opened, undefined);
  for (const status of ['failed', 'stale', 'verifying', 'permission_denied']) assert.equal(canShowSelectedWorkspaceReadSource({ ...partial, status }, access, 'subscriptions', now), false);
  assert.equal(canShowSelectedWorkspaceReadSource(partial, { ...access, exchangeId: 'other' }, 'subscriptions', now), false);
  assert.equal(canShowSelectedWorkspaceReadSource(partial, access, 'subscriptions', Date.parse(fact.expiresAt)), false);
  assert.equal(canShowSelectedWorkspaceReadSource({ ...partial, readSources: [{ ...partial.readSources[0], permission: 'denied' }] }, access, 'subscriptions', now), false);
});

test('Workspace bearer status and expiry fence visible facts without implicit exchange', () => {
  const now = Date.parse('2026-01-07T00:00:00Z');
  const access = { status: 'ready', expiresAt: '2026-01-08T00:00:00Z', exchangeId: 'exchange-1' };
  assert.equal(canShowSelectedWorkspaceFacts(fact, access, now), true);
  for (const status of ['required','exchanging','failed','permission_denied']) {
    assert.equal(canShowSelectedWorkspaceFacts(fact, { ...access, status }, now), false, status);
  }
  assert.equal(canShowSelectedWorkspaceFacts(fact, access, Date.parse(access.expiresAt)), false);
  assert.equal(canShowSelectedWorkspaceFacts(fact, null, now), false);
});

test('delayed old facts cannot pair with ready access from a new exchange', async () => {
  const now = Date.parse('2026-01-07T00:00:00Z');
  const oldFacts = { ...fact, exchangeId: 'exchange-old' };
  let finishNewAccess;
  const oldFactsGet = Promise.resolve(oldFacts); // other tab has not exchanged yet
  const newAccessGet = new Promise((resolve) => { finishNewAccess = resolve; });
  const mixedPoll = Promise.all([oldFactsGet, newAccessGet]);
  await oldFactsGet;
  finishNewAccess({ status: 'ready', expiresAt: '2026-01-08T00:00:00Z', exchangeId: 'exchange-new' });
  const [factsFromOldSnapshot, accessFromNewSnapshot] = await mixedPoll;
  assert.equal(canShowSelectedWorkspaceFacts(factsFromOldSnapshot, accessFromNewSnapshot, now), false);
  assert.equal(canShowSelectedWorkspaceFacts({ ...fact, exchangeId: 'exchange-new' }, accessFromNewSnapshot, now), true);
  assert.equal(canShowSelectedWorkspaceFacts(factsFromOldSnapshot, { ...accessFromNewSnapshot, exchangeId: undefined }, now), false);
});

test('old poll cannot restore prior success over pending or failed POST', () => {
  const gate = createWorkspaceRequestGate();
  const oldPoll = gate.beginPoll();
  assert.notEqual(oldPoll, null);
  const mutation = gate.beginMutation();
  assert.equal(gate.beginPoll(), null);
  assert.equal(gate.acceptPoll(oldPoll), false);
  assert.equal(gate.acceptMutation(mutation), true);
  assert.equal(gate.acceptPoll(oldPoll), false);
  const nextPoll = gate.beginPoll();
  assert.notEqual(nextPoll, null);
  gate.invalidate();
  assert.equal(gate.acceptPoll(nextPoll), false);
  assert.equal(gate.acceptMutation(mutation), false);
});

test('older POST completion cannot end or reveal a newer in-flight verification', () => {
  const gate = createWorkspaceRequestGate();
  const older = gate.beginMutation();
  const newer = gate.beginMutation();
  assert.equal(gate.isCurrentMutation(older), false);
  assert.equal(gate.acceptMutation(older), false);
  assert.equal(gate.beginPoll(), null);
  assert.equal(gate.isCurrentMutation(newer), true);
  assert.equal(gate.acceptMutation(newer), true);
});


test('operation admission uses verified own-mother management authority and gives actionable blockers', () => {
  const now = Date.parse('2026-01-07T00:00:00Z');
  const access = { status: 'ready', expiresAt: '2026-01-08T00:00:00Z', exchangeId: 'exchange-1' };
  assert.deepEqual(selectedWorkspaceOperationState({ ...fact, canManage: true, motherRole: 'owner' }, access, now), { ready: true, status: '可以操作' });
  assert.equal(selectedWorkspaceOperationState({ ...fact, canManage: true, motherRole: 'admin' }, access, now).ready, true);
  assert.deepEqual(selectedWorkspaceOperationState({ ...fact, motherRole: 'member' }, access, now), { ready: false, status: '当前母号是普通成员，无法管理该空间' });
  assert.match(selectedWorkspaceOperationState({ ...fact, motherRole: 'unknown' }, access, now).status, /未获取母号的管理身份/);
  const owner = { ...fact, canManage: true, motherRole: 'owner' };
  assert.equal(selectedWorkspaceOperationState({ ...owner, exchangeId: 'other-exchange' }, access, now).ready, false);
  assert.equal(selectedWorkspaceOperationState(owner, { ...access, status: 'required' }, now).ready, false);
  assert.equal(selectedWorkspaceOperationState(owner, access, Date.parse(access.expiresAt)).ready, false);
  for (const status of ['partial', 'failed', 'stale', 'verifying']) assert.equal(selectedWorkspaceOperationState({ ...owner, status }, access, now).ready, false, status);
});
