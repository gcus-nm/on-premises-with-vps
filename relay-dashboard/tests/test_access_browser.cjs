const assert = require('node:assert/strict');
const { webcrypto } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '../static/app.js'), 'utf8');
const start = source.indexOf('function createIdempotencyKey()');
const end = source.indexOf('async function saveAccessGroup()', start);
assert.ok(start >= 0 && end > start);

function browser(confirmed = true) {
  const calls = [];
  // HTTP環境と同じくrandomUUIDは提供しない。
  const context = vm.createContext({
    crypto: { getRandomValues: webcrypto.getRandomValues.bind(webcrypto) },
    Uint8Array,
    window: { confirm: () => confirmed },
    api: async (url, options) => {
      calls.push({ url, options });
      return url.endsWith('/access-preview')
        ? { revision: 'preview-revision', changes: [] }
        : { ok: true };
    },
  });
  vm.runInContext(source.slice(start, end), context);
  return { context, calls };
}

test('randomUUIDがない環境でもAPIの形式に合う重複しないキーを生成できる', () => {
  const { context } = browser();
  assert.equal(context.crypto.randomUUID, undefined);
  const keys = Array.from({ length: 1000 }, () => context.createIdempotencyKey());
  for (const key of keys) assert.match(key, /^access-[0-9a-f]{32}$/);
  assert.equal(new Set(keys).size, keys.length);
});

test('グループ作成・更新・削除とPeer割り当てがプレビュー後に保存できる', async () => {
  const { context, calls } = browser();
  const endpoints = [
    ['POST', '/api/wireguard/access-groups', 'group-create'],
    ['PUT', '/api/wireguard/access-groups/home', 'group-update'],
    ['DELETE', '/api/wireguard/access-groups/home', 'group-delete'],
    ['PUT', '/api/wireguard/peers/laptop/access', 'assign'],
  ];
  const keys = [];
  for (const [method, url, action] of endpoints) {
    const request = { action, name: 'home' };
    const result = await context.confirmAccessChange(request, url, method);
    assert.equal(result.ok, true);
    const [preview, saved] = calls.splice(0);
    assert.equal(preview.url, '/api/wireguard/access-preview');
    assert.equal(preview.options.method, 'POST');
    assert.equal(saved.url, url);
    assert.equal(saved.options.method, method);
    assert.equal(saved.options.body.revision, 'preview-revision');
    assert.equal(saved.options.body.action, action);
    const key = saved.options.headers['Idempotency-Key'];
    assert.match(key, /^access-[0-9a-f]{32}$/);
    keys.push(key);
  }
  assert.equal(new Set(keys).size, endpoints.length);
});

test('確認をキャンセルすると保存APIを呼ばない', async () => {
  const { context, calls } = browser(false);
  assert.equal(await context.confirmAccessChange({}, '/api/wireguard/access-groups', 'POST'), null);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, '/api/wireguard/access-preview');
});
