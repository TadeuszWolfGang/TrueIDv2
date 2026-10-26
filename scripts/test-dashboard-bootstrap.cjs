'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const assets = path.join(__dirname, '..', 'apps', 'web', 'assets');
const html = fs.readFileSync(path.join(assets, 'index.html'), 'utf8');
const flushTasks = () => new Promise(setImmediate);

function createDashboard({ sessionStatus = 200, streamError = null } = {}) {
  const requests = [];
  const streams = [];
  const errors = [];
  const listeners = new Map();
  const elements = new Map(Array.from(html.matchAll(/\bid="([^"]+)"/g), ([, id]) => [id, {
    hidden: true,
    value: '',
    textContent: '',
    innerHTML: '',
    classList: { add() {}, remove() {}, toggle() {} },
    querySelectorAll: () => [],
  }]));
  const document = {
    readyState: 'loading',
    getElementById: (id) => elements.get(id) || null,
    querySelectorAll: () => [],
    querySelector: () => null,
    addEventListener(type, callback, options) {
      const entries = listeners.get(type) || [];
      entries.push({ callback, once: Boolean(options && options.once) });
      listeners.set(type, entries);
    },
  };
  const context = vm.createContext({
    document,
    location: '/',
    console: { error: (...args) => errors.push(args) },
    localStorage: { getItem: () => 'off' },
    addEventListener() {},
    setInterval: () => 1,
    clearInterval() {},
    setTimeout: () => 1,
    URLSearchParams,
    async fetch(url, options) {
      requests.push({ url, options });
      const status = url === '/api/auth/me' ? sessionStatus : 200;
      return {
        status,
        ok: status === 200,
        async json() {
          if (url === '/api/auth/me') {
            return { user: { username: 'fixture', role: 'Admin' }, force_password_change: false, active_sessions_count: 1 };
          }
          return url.startsWith('/api/v2/search?') ? { mappings: { data: [], total: 0 } } : {};
        },
      };
    },
    EventSource: class {
      constructor(url) {
        if (streamError) throw streamError;
        streams.push(url);
      }
      addEventListener() {}
    },
  });
  context.window = context;

  function load(name) {
    const filename = path.join(assets, 'js', name);
    vm.runInContext(fs.readFileSync(filename, 'utf8'), context, { filename });
  }
  load('utils.js');
  load('api.js');
  load('app.js');

  return {
    context, elements, errors, requests, streams,
    loadMappings: () => load('mappings.js'),
    domReady() {
      document.readyState = 'interactive';
      const entries = listeners.get('DOMContentLoaded') || [];
      listeners.set('DOMContentLoaded', entries.filter((entry) => !entry.once));
      for (const { callback } of entries) callback();
    },
  };
}

test('fast session response waits for dashboard dependencies before initialization', async () => {
  const dashboard = createDashboard();
  // A parser-blocking module download can yield while a fast /me response completes.
  await flushTasks();
  assert.equal(dashboard.requests.length, 0, 'authentication must wait until dependency scripts finish');
  assert.equal(dashboard.context.location, '/');

  dashboard.loadMappings();
  dashboard.domReady();
  await flushTasks();

  assert.equal(dashboard.context.location, '/');
  assert.equal(dashboard.elements.get('user-bar').hidden, false);
  assert.match(dashboard.elements.get('user-info').textContent, /fixture \(Admin\)/);
  assert.ok(dashboard.requests.some(({ url }) => url.startsWith('/api/v2/search?')));
  assert.equal(dashboard.requests.find(({ url }) => url === '/api/auth/me').options.credentials, 'include');
  assert.deepEqual(dashboard.streams, ['/api/v2/events/stream']);
  assert.deepEqual(dashboard.errors, []);

  dashboard.domReady();
  await flushTasks();
  assert.equal(dashboard.requests.filter(({ url }) => url === '/api/auth/me').length, 1);
});

test('unauthorized session still redirects to login', async () => {
  const dashboard = createDashboard({ sessionStatus: 401 });
  dashboard.loadMappings();
  dashboard.domReady();
  await flushTasks();

  assert.equal(dashboard.context.location, '/login.html');
  assert.deepEqual(dashboard.streams, []);
  assert.deepEqual(dashboard.errors, []);
});

test('dashboard initialization errors are reported without sensitive error details', async () => {
  const sensitiveDetail = 'sensitive-error-fixture';
  const dashboard = createDashboard({ streamError: new Error(sensitiveDetail) });
  dashboard.loadMappings();
  dashboard.domReady();
  await flushTasks();

  assert.equal(dashboard.context.location, '/login.html');
  assert.equal(dashboard.errors.length, 1);
  assert.equal(dashboard.errors[0].length, 1);
  assert.match(dashboard.errors[0][0], /Dashboard initialization failed/);
  assert.ok(!JSON.stringify(dashboard.errors).includes(sensitiveDetail));
});
