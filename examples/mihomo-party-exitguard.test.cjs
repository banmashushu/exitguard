const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(__dirname + '/mihomo-party-exitguard.js', 'utf8');
function run(config, target = '') {
  const context = vm.createContext({input: config, target});
  vm.runInContext(source + '\nTARGET_PROXY = target; result = main(input);', context);
  return context.result;
}
function config() {
  return {rules: ['MATCH,Group'], proxies: [{name: 'Fixed leaf', type: 'ss', server: 'example.test', port: 443}], 'proxy-groups': [{name: 'Group', type: 'select', proxies: ['Fixed leaf']}], 'mixed-port': 7890, authentication: ['keep:unchanged'], listeners: [{name: 'existing', type: 'socks', listen: '127.0.0.1', port: 7891}], 'system-proxy': true};
}
const initial = config();
assert.equal(run(initial), initial, 'empty default must be no-op');
assert.deepEqual(initial, config(), 'default changed config');
const valid = config();
const original = structuredClone(valid);
assert.equal(run(valid, 'Fixed leaf'), valid);
assert.deepEqual(valid.listeners.slice(0, 1), original.listeners);
assert.deepEqual(JSON.parse(JSON.stringify(valid.listeners[1])), {name: 'exitguard-in', type: 'http', listen: '127.0.0.1', port: 17891, proxy: 'Fixed leaf', users: []});
const expected = {...original, listeners: valid.listeners};
assert.deepEqual(valid, expected, 'unrelated config changed');
run(valid, 'Fixed leaf');
assert.equal(valid.listeners.length, 2, 'override must be idempotent');
for (const target of ['DIRECT', 'direct', 'REJECT', 'REJECT-DROP', 'PASS', 'COMPATIBLE', 'GLOBAL', 'Group', 'Missing leaf', ' Fixed leaf ', '\nFixed leaf', 123]) {
  const c = config(), before = structuredClone(c);
  assert.throws(() => run(c, target), undefined, 'accepted unsafe target ' + target);
  assert.deepEqual(c, before, 'failed validation mutated config');
}
for (const mutate of [
  c => c.listeners.push({name: 'occupied', type: 'http', port: 17891}),
  c => c.listeners.push({name: 'range', type: 'http', port: '17890-17895'}),
  c => c.listeners.push({name: 'list', type: 'http', port: '7890,17891'}),
  c => c.listeners.push({name: 'uncertain', type: 'http', port: 'unknown'}),
  c => c.listeners.push({name: 'spaces', type: 'http', port: ' 17891 '}),
  c => c.listeners.push({name: 'exitguard-in', type: 'http', port: 17892}),
  c => c['mixed-port'] = 17891,
  c => c.port = '17891',
  c => c.listeners = {},
  c => c['proxy-groups'].push({name: 'Fixed leaf', type: 'select'}),
  c => c.proxies.push({...c.proxies[0]}),
  c => c.proxies[0].type = 'direct',
  c => c.proxies[0]['dialer-proxy'] = 'Group',
  c => c.proxies[0].type = 'select',
  c => c.proxies[0].type = 'mystery',
]) {
  const c = config(); mutate(c); const before = structuredClone(c);
  assert.throws(() => run(c, 'Fixed leaf'));
  assert.deepEqual(c, before, 'conflict must not mutate config');
}
assert.equal(run(null), null, 'unset target must remain safe on missing config');
console.log('Mihomo Party override semantics: passed');
