import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import '@xterm/xterm/css/xterm.css';
import './styles.css';

const BASE_PATH = import.meta.env.BASE_URL;
const app = document.querySelector<HTMLDivElement>('#app');
const TERMINAL_KEY_CONFIG_STORAGE = 'termlens.terminalKeyConfig.v1';
let activeTerminalFit: (() => void) | null = null;
let activeTerminalInput: ((data: string) => void) | null = null;
let activeTerminalFocus: (() => void) | null = null;
let activeTerminalBlur: (() => void) | null = null;
let terminalViewportCleanup: (() => void) | null = null;
const terminalModifierState = new Set<TerminalModifier>();

if (!app) throw new Error('Missing #app root');

type ApiOptions = RequestInit & { json?: unknown };

interface Target {
  id: number;
  kind?: 'ssh' | 'private';
  name: string;
  host: string;
  port: number;
  sshUsername: string;
  online?: boolean;
  agentEnrolled?: boolean;
  lastSeenAt?: string;
  disabled?: boolean;
}

interface User {
  id: number;
  username: string;
  displayName: string;
  role: 'admin' | 'user';
  totpEnabled: boolean;
  disabled: boolean;
}

interface PrivateEnrollment {
  token: string;
  expiresAt: string;
  command: string;
}

interface TerminalKeyAction {
  id: string;
  label: string;
  data: string;
  title: string;
  wide?: boolean;
  useModifiers?: boolean;
}

type TerminalModifier = 'ctrl' | 'alt' | 'shift' | 'meta';
type TerminalKeyProfile = 'auto' | 'macos' | 'windows' | 'linux';
type TerminalToolbarItemType = 'modifier' | 'key' | 'utility';

interface TerminalModifierAction {
  id: TerminalModifier;
  label: string;
  title: string;
  labels?: Partial<Record<TerminalEffectivePlatform, string>>;
  titles?: Partial<Record<TerminalEffectivePlatform, string>>;
}

interface TerminalUtilityAction {
  id: string;
  label: string;
  title: string;
  wide?: boolean;
}

interface TerminalToolbarItem {
  type: TerminalToolbarItemType;
  id: string;
}

interface TerminalKeyConfig {
  profile: TerminalKeyProfile;
  order: string[];
  hidden: string[];
}

type TerminalEffectivePlatform = Exclude<TerminalKeyProfile, 'auto'>;

const TERMINAL_MODIFIER_ACTIONS: TerminalModifierAction[] = [
  { id: 'ctrl', label: 'Ctrl', title: '下一个按键使用 Ctrl' },
  { id: 'alt', label: 'Alt', title: '下一个按键使用 Alt/Meta' },
  { id: 'shift', label: 'Shift', title: '下一个按键使用 Shift' },
  {
    id: 'meta',
    label: 'Meta',
    title: '下一个按键使用 Meta/Super',
    labels: { macos: 'Cmd', windows: 'Win', linux: 'Super' },
    titles: {
      macos: '下一个按键使用 Command/Meta',
      windows: '下一个按键使用 Windows/Meta',
      linux: '下一个按键使用 Super/Meta'
    }
  }
];

const TERMINAL_KEY_ACTIONS: TerminalKeyAction[] = [
  { id: 'ctrl-alt-del', label: 'Ctrl+Alt+Del', data: '\x1b[3;7~', title: 'Ctrl+Alt+Del', wide: true, useModifiers: false },
  { id: 'esc', label: 'Esc', data: '\x1b', title: 'Escape' },
  { id: 'tab', label: 'Tab', data: '\t', title: 'Tab' },
  { id: 'vim-insert', label: 'Vim i', data: 'i', title: 'Vim insert mode', wide: true, useModifiers: false },
  { id: 'vim-command', label: 'Vim :', data: '\x1b:', title: 'Vim command mode', wide: true, useModifiers: false },
  { id: 'vim-save-quit', label: ':wq', data: '\x1b:wq\r', title: 'Vim save and quit', useModifiers: false },
  { id: 'vim-quit-force', label: ':q!', data: '\x1b:q!\r', title: 'Vim quit without saving', useModifiers: false },
  { id: 'ctrl-a', label: 'Ctrl+A', data: '\x01', title: 'Ctrl+A', useModifiers: false },
  { id: 'ctrl-c', label: 'Ctrl+C', data: '\x03', title: 'Ctrl+C', useModifiers: false },
  { id: 'ctrl-d', label: 'Ctrl+D', data: '\x04', title: 'Ctrl+D', useModifiers: false },
  { id: 'ctrl-e', label: 'Ctrl+E', data: '\x05', title: 'Ctrl+E', useModifiers: false },
  { id: 'ctrl-l', label: 'Ctrl+L', data: '\x0c', title: 'Ctrl+L', useModifiers: false },
  { id: 'ctrl-r', label: 'Ctrl+R', data: '\x12', title: 'Ctrl+R', useModifiers: false },
  { id: 'ctrl-u', label: 'Ctrl+U', data: '\x15', title: 'Ctrl+U', useModifiers: false },
  { id: 'ctrl-w', label: 'Ctrl+W', data: '\x17', title: 'Ctrl+W', useModifiers: false },
  { id: 'ctrl-z', label: 'Ctrl+Z', data: '\x1a', title: 'Ctrl+Z', useModifiers: false },
  { id: 'up', label: '↑', data: '\x1b[A', title: 'Arrow Up' },
  { id: 'down', label: '↓', data: '\x1b[B', title: 'Arrow Down' },
  { id: 'left', label: '←', data: '\x1b[D', title: 'Arrow Left' },
  { id: 'right', label: '→', data: '\x1b[C', title: 'Arrow Right' },
  { id: 'home', label: 'Home', data: '\x1b[H', title: 'Home' },
  { id: 'end', label: 'End', data: '\x1b[F', title: 'End' },
  { id: 'page-up', label: 'PgUp', data: '\x1b[5~', title: 'Page Up' },
  { id: 'page-down', label: 'PgDn', data: '\x1b[6~', title: 'Page Down' },
  { id: 'f1', label: 'F1', data: '\x1bOP', title: 'F1' },
  { id: 'f2', label: 'F2', data: '\x1bOQ', title: 'F2' },
  { id: 'f3', label: 'F3', data: '\x1bOR', title: 'F3' },
  { id: 'f4', label: 'F4', data: '\x1bOS', title: 'F4' },
  { id: 'f5', label: 'F5', data: '\x1b[15~', title: 'F5' },
  { id: 'f6', label: 'F6', data: '\x1b[17~', title: 'F6' },
  { id: 'f7', label: 'F7', data: '\x1b[18~', title: 'F7' },
  { id: 'f8', label: 'F8', data: '\x1b[19~', title: 'F8' },
  { id: 'f9', label: 'F9', data: '\x1b[20~', title: 'F9' },
  { id: 'f10', label: 'F10', data: '\x1b[21~', title: 'F10' },
  { id: 'f11', label: 'F11', data: '\x1b[23~', title: 'F11' },
  { id: 'f12', label: 'F12', data: '\x1b[24~', title: 'F12' },
  { id: 'enter', label: 'Enter', data: '\r', title: 'Enter' },
  { id: 'backspace', label: '⌫', data: '\x7f', title: 'Backspace' },
  { id: 'delete', label: 'Del', data: '\x1b[3~', title: 'Delete' },
  { id: 'pipe', label: '|', data: '|', title: 'Pipe' },
  { id: 'tilde', label: '~', data: '~', title: 'Tilde' },
  { id: 'slash', label: '/', data: '/', title: 'Slash' },
  { id: 'dash', label: '-', data: '-', title: 'Dash' },
  { id: 'underscore', label: '_', data: '_', title: 'Underscore' }
];

const TERMINAL_UTILITY_ACTIONS: TerminalUtilityAction[] = [
  { id: 'keyboard', label: '键盘', title: '显示或隐藏系统键盘', wide: true }
];

const TERMINAL_ARROW_SEQUENCES: Record<string, string> = {
  '\x1b[A': 'A',
  '\x1b[B': 'B',
  '\x1b[C': 'C',
  '\x1b[D': 'D'
};

const TERMINAL_HOME_END_SEQUENCES: Record<string, string> = {
  '\x1b[H': 'H',
  '\x1b[F': 'F'
};

const TERMINAL_SS3_SEQUENCES: Record<string, string> = {
  '\x1bOP': 'P',
  '\x1bOQ': 'Q',
  '\x1bOR': 'R',
  '\x1bOS': 'S'
};

const TERMINAL_TILDE_SEQUENCES: Record<string, string> = {
  '\x1b[3~': '3',
  '\x1b[5~': '5',
  '\x1b[6~': '6',
  '\x1b[15~': '15',
  '\x1b[17~': '17',
  '\x1b[18~': '18',
  '\x1b[19~': '19',
  '\x1b[20~': '20',
  '\x1b[21~': '21',
  '\x1b[23~': '23',
  '\x1b[24~': '24'
};

const SHIFTED_TERMINAL_CHARS: Record<string, string> = {
  '`': '~',
  '1': '!',
  '2': '@',
  '3': '#',
  '4': '$',
  '5': '%',
  '6': '^',
  '7': '&',
  '8': '*',
  '9': '(',
  '0': ')',
  '-': '_',
  '=': '+',
  '[': '{',
  ']': '}',
  '\\': '|',
  ';': ':',
  "'": '"',
  ',': '<',
  '.': '>',
  '/': '?'
};

function terminalItemKey(item: TerminalToolbarItem) {
  return `${item.type}:${item.id}`;
}

function parseTerminalItemKey(key: string): TerminalToolbarItem | null {
  const [type, id] = key.split(':');
  if ((type === 'modifier' || type === 'key' || type === 'utility') && id) {
    return { type, id };
  }
  return null;
}

function terminalDefaultOrder() {
  return [
    ...TERMINAL_MODIFIER_ACTIONS.map((action) => terminalItemKey({ type: 'modifier', id: action.id })),
    ...TERMINAL_KEY_ACTIONS.map((action) => terminalItemKey({ type: 'key', id: action.id })),
    ...TERMINAL_UTILITY_ACTIONS.map((action) => terminalItemKey({ type: 'utility', id: action.id }))
  ];
}

function knownTerminalItemKeys() {
  return new Set(terminalDefaultOrder());
}

function isTerminalKeyProfile(value: unknown): value is TerminalKeyProfile {
  return value === 'auto' || value === 'macos' || value === 'windows' || value === 'linux';
}

function normalizeTerminalKeyConfig(value: Partial<TerminalKeyConfig> = {}): TerminalKeyConfig {
  const defaultOrder = terminalDefaultOrder();
  const known = new Set(defaultOrder);
  const order: string[] = [];

  for (const key of Array.isArray(value.order) ? value.order : []) {
    if (known.has(key) && !order.includes(key)) order.push(key);
  }
  for (let defaultIndex = 0; defaultIndex < defaultOrder.length; defaultIndex += 1) {
    const key = defaultOrder[defaultIndex];
    if (order.includes(key)) continue;

    let insertAt = -1;
    for (let previousIndex = defaultIndex - 1; previousIndex >= 0; previousIndex -= 1) {
      const existingIndex = order.indexOf(defaultOrder[previousIndex]);
      if (existingIndex >= 0) {
        insertAt = existingIndex + 1;
        break;
      }
    }

    if (insertAt >= 0) {
      order.splice(insertAt, 0, key);
    } else {
      order.push(key);
    }
  }

  const hidden = Array.isArray(value.hidden)
    ? Array.from(new Set(value.hidden.filter((key) => known.has(key))))
    : [];

  return {
    profile: isTerminalKeyProfile(value.profile) ? value.profile : 'auto',
    order,
    hidden
  };
}

function loadTerminalKeyConfig() {
  try {
    const stored = localStorage.getItem(TERMINAL_KEY_CONFIG_STORAGE);
    return normalizeTerminalKeyConfig(stored ? JSON.parse(stored) : {});
  } catch (error) {
    return normalizeTerminalKeyConfig();
  }
}

function saveTerminalKeyConfig(config: TerminalKeyConfig) {
  try {
    localStorage.setItem(TERMINAL_KEY_CONFIG_STORAGE, JSON.stringify(normalizeTerminalKeyConfig(config)));
  } catch (error) {
    showMessage('特殊键配置未能保存到当前浏览器。', 'error');
  }
}

function detectedTerminalPlatform(): TerminalEffectivePlatform {
  const userAgent = navigator.userAgent.toLowerCase();
  if (/mac|iphone|ipad|ipod/.test(userAgent)) return 'macos';
  if (/win/.test(userAgent)) return 'windows';
  return 'linux';
}

function effectiveTerminalPlatform(profile: TerminalKeyProfile): TerminalEffectivePlatform {
  return profile === 'auto' ? detectedTerminalPlatform() : profile;
}

function terminalModifierLabel(action: TerminalModifierAction, config: TerminalKeyConfig) {
  return action.labels?.[effectiveTerminalPlatform(config.profile)] || action.label;
}

function terminalModifierTitle(action: TerminalModifierAction, config: TerminalKeyConfig) {
  return action.titles?.[effectiveTerminalPlatform(config.profile)] || action.title;
}

function terminalToolbarItems(config: TerminalKeyConfig) {
  const known = knownTerminalItemKeys();
  const hidden = new Set(config.hidden);
  return config.order
    .filter((key) => known.has(key) && !hidden.has(key))
    .map(parseTerminalItemKey)
    .filter((item): item is TerminalToolbarItem => Boolean(item));
}

function terminalToolbarItemLabel(key: string, config: TerminalKeyConfig) {
  const item = parseTerminalItemKey(key);
  if (!item) return key;
  if (item.type === 'modifier') {
    const action = TERMINAL_MODIFIER_ACTIONS.find((candidate) => candidate.id === item.id);
    return action ? terminalModifierLabel(action, config) : item.id;
  }
  if (item.type === 'utility') {
    const action = TERMINAL_UTILITY_ACTIONS.find((candidate) => candidate.id === item.id);
    return action?.label || item.id;
  }
  const action = TERMINAL_KEY_ACTIONS.find((candidate) => candidate.id === item.id);
  return action?.label || item.id;
}

route().catch((error) => renderError(error));

async function route() {
  const relative = relativePath();
  if (relative.startsWith('access/')) {
    const token = relative.slice('access/'.length).split('/')[0];
    await renderAccess(token);
    return;
  }
  if (relative.startsWith('terminal')) {
    await renderTerminal(new URLSearchParams(location.search).get('ticket') || '');
    return;
  }
  if (relative.startsWith('admin')) {
    await renderAdmin();
    return;
  }
  await renderHome();
}

async function api<T>(path: string, options: ApiOptions = {}): Promise<T> {
  const response = await fetch(`${BASE_PATH}api/${path.replace(/^\/+/, '')}`, {
    ...options,
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {})
    },
    body: options.json === undefined ? options.body : JSON.stringify(options.json)
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.error || `Request failed: ${response.status}`);
  }
  return payload as T;
}

function relativePath() {
  const path = location.pathname;
  if (path === BASE_PATH.slice(0, -1)) return '';
  return path.startsWith(BASE_PATH) ? path.slice(BASE_PATH.length) : '';
}

function setView(html: string) {
  terminalViewportCleanup?.();
  terminalViewportCleanup = null;
  terminalModifierState.clear();
  activeTerminalFit = null;
  activeTerminalInput = null;
  activeTerminalFocus = null;
  activeTerminalBlur = null;
  document.body.classList.remove('terminal-page');
  document.body.classList.remove('terminal-immersive-active');
  document.documentElement.style.removeProperty('--terminal-viewport-height');
  app.innerHTML = html;
}

function escapeHtml(value: unknown) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function showMessage(message: string, kind: 'ok' | 'error' = 'ok') {
  const node = document.querySelector<HTMLDivElement>('#message');
  if (!node) return;
  node.textContent = message;
  node.className = `message ${kind}`;
}

function showAccessLinkActions(accessUrl: string, title: string) {
  const node = document.querySelector<HTMLDivElement>('#message');
  if (!node) return;
  node.className = 'message access-link-result';
  node.innerHTML = `
    <div>
      <strong>${escapeHtml(title)}</strong>
      <code>${escapeHtml(accessUrl)}</code>
    </div>
    <div class="access-link-actions">
      <button class="button small" type="button" data-copy-access-url="${escapeHtml(accessUrl)}">复制</button>
      <button class="button small primary" type="button" data-open-access-url="${escapeHtml(accessUrl)}">复制并打开</button>
    </div>
  `;
  node.querySelector<HTMLButtonElement>('[data-copy-access-url]')?.addEventListener('click', async (event) => {
    const url = event.currentTarget.dataset.copyAccessUrl || accessUrl;
    try {
      await copyText(url);
      event.currentTarget.textContent = '已复制';
    } catch (error) {
      showMessage((error as Error).message, 'error');
    }
  });
  node.querySelector<HTMLButtonElement>('[data-open-access-url]')?.addEventListener('click', async (event) => {
    const url = event.currentTarget.dataset.openAccessUrl || accessUrl;
    try {
      await copyText(url);
    } catch (error) {
      // Opening the generated link is the primary action here; copying is best effort.
    }
    location.href = url;
  });
}

function showPrivateEnrollmentActions(enrollment: PrivateEnrollment) {
  const node = document.querySelector<HTMLDivElement>('#message');
  if (!node) return;
  node.className = 'message access-link-result';
  node.innerHTML = `
    <div>
      <strong>Agent 注册命令</strong>
      <code>${escapeHtml(enrollment.command)}</code>
      <span>有效期至 ${escapeHtml(enrollment.expiresAt)}。注册命令包含一次性 token，请通过安全渠道使用。</span>
    </div>
    <div class="access-link-actions">
      <button class="button small primary" type="button" data-copy-agent-command="${escapeHtml(enrollment.command)}">复制命令</button>
    </div>
  `;
  node.querySelector<HTMLButtonElement>('[data-copy-agent-command]')?.addEventListener('click', async (event) => {
    const command = event.currentTarget.dataset.copyAgentCommand || enrollment.command;
    try {
      await copyText(command);
      event.currentTarget.textContent = '已复制';
    } catch (error) {
      showMessage((error as Error).message, 'error');
    }
  });
}

async function copyText(value: string) {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(value);
    return;
  }
  const textarea = document.createElement('textarea');
  textarea.value = value;
  textarea.setAttribute('readonly', '');
  textarea.style.position = 'fixed';
  textarea.style.left = '-9999px';
  document.body.append(textarea);
  textarea.select();
  const copied = document.execCommand('copy');
  textarea.remove();
  if (!copied) throw new Error('复制失败，请手动复制访问链接。');
}

async function renderHome() {
  const me = await api<{ authenticated: boolean; user?: User }>('me');
  setView(shell(`
    <section class="hero-panel">
      <div>
        <p class="eyebrow">WebSSH access gateway</p>
        <h1>TermLens</h1>
        <p>通过独立访问链接、登录密码和 TOTP 双因子验证进入授权 SSH 终端。</p>
      </div>
      <div class="hero-actions">
        ${me.authenticated && me.user?.role === 'admin' ? `<a class="button primary" href="${BASE_PATH}admin">管理后台</a>` : ''}
        <a class="button" href="https://www.difflens.io/">返回 DiffLens</a>
      </div>
    </section>
    <section class="panel">
      <h2>访问方式</h2>
      <p class="muted">终端入口由管理员分配。请使用你的专属访问链接登录，不能从公开首页直接进入终端。</p>
    </section>
  `));
}

async function renderAccess(token: string) {
  const status = await api<{
    username: string;
    displayName: string;
    authenticated: boolean;
    totpEnabled: boolean;
  }>(`access/${encodeURIComponent(token)}`);

  if (status.authenticated) {
    await renderLaunch(token);
    return;
  }

  setView(shell(`
    <section class="auth-layout">
      <form id="loginForm" class="panel auth-panel">
        <p class="eyebrow">Private access link</p>
        <h1>登录 TermLens</h1>
        <p class="muted">账号：${escapeHtml(status.displayName || status.username)}</p>
        <label>
          <span>密码</span>
          <input name="password" type="password" autocomplete="current-password" required />
        </label>
        <label>
          <span>TOTP 验证码</span>
          <input name="totpCode" inputmode="numeric" autocomplete="one-time-code" placeholder="${status.totpEnabled ? '6 位验证码' : '首次登录后扫码设置'}" />
        </label>
        <button class="button primary" type="submit">登录</button>
        <div id="message" class="message"></div>
      </form>
    </section>
  `));

  document.querySelector<HTMLFormElement>('#loginForm')?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      const result = await api<{
        ok?: boolean;
        mfaSetupRequired?: boolean;
        challenge?: string;
        qrDataUrl?: string;
      }>(`access/${encodeURIComponent(token)}/login`, {
        method: 'POST',
        json: {
          password: form.get('password'),
          totpCode: form.get('totpCode')
        }
      });
      if (result.mfaSetupRequired && result.challenge && result.qrDataUrl) {
        renderMfaSetup(token, result.challenge, result.qrDataUrl);
        return;
      }
      await renderLaunch(token);
    } catch (error) {
      showMessage((error as Error).message, 'error');
    }
  });
}

function renderMfaSetup(token: string, challenge: string, qrDataUrl: string) {
  setView(shell(`
    <section class="auth-layout">
      <form id="mfaForm" class="panel auth-panel">
        <p class="eyebrow">Two-factor setup</p>
        <h1>设置双因子验证</h1>
        <p class="muted">使用 Google Authenticator、1Password、Authy 等 TOTP 应用扫描二维码，然后输入 6 位验证码。</p>
        <div class="qr-box"><img id="mfaQr" alt="TOTP QR code" /></div>
        <label>
          <span>TOTP 验证码</span>
          <input name="totpCode" inputmode="numeric" autocomplete="one-time-code" required />
        </label>
        <button class="button primary" type="submit">完成设置并登录</button>
        <div id="message" class="message"></div>
      </form>
    </section>
  `));
  const qr = document.querySelector<HTMLImageElement>('#mfaQr');
  if (qr) qr.src = qrDataUrl;
  document.querySelector<HTMLFormElement>('#mfaForm')?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      await api(`access/${encodeURIComponent(token)}/mfa/setup/verify`, {
        method: 'POST',
        json: {
          challenge,
          totpCode: form.get('totpCode')
        }
      });
      await renderLaunch(token);
    } catch (error) {
      showMessage((error as Error).message, 'error');
    }
  });
}

async function renderLaunch(token: string) {
  const payload = await api<{ user: User; targets: Target[] }>(`launch/${encodeURIComponent(token)}`);
  setView(shell(`
    <section class="workspace-head">
      <div>
        <p class="eyebrow">Authorized targets</p>
        <h1>选择 SSH 目标</h1>
        <p class="muted">当前登录：${escapeHtml(payload.user.displayName || payload.user.username)}</p>
      </div>
      <div class="row-actions">
        ${payload.user.role === 'admin' ? `<a class="button" href="${BASE_PATH}admin">管理后台</a>` : ''}
        <button id="logoutButton" class="button ghost" type="button">退出</button>
      </div>
    </section>
    <section class="target-grid">
      ${payload.targets.length ? payload.targets.map((target) => targetCard(target)).join('') : '<div class="empty">当前账号没有可连接的 SSH 目标。</div>'}
    </section>
    <div id="message" class="message"></div>
  `));

  document.querySelector('#logoutButton')?.addEventListener('click', async () => {
    await api('logout', { method: 'POST', json: {} });
    location.href = BASE_PATH;
  });

  for (const button of document.querySelectorAll<HTMLButtonElement>('[data-connect-target]')) {
    button.addEventListener('click', async () => {
      const targetId = Number(button.dataset.connectTarget);
      const targetKind = button.dataset.targetKind === 'private' ? 'private' : 'ssh';
      try {
        const ticket = await api<{ terminalUrl: string }>('terminal/tickets', {
          method: 'POST',
          json: { accessToken: token, targetId, targetKind }
        });
        location.href = ticket.terminalUrl;
      } catch (error) {
        showMessage((error as Error).message, 'error');
      }
    });
  }
}

function targetCard(target: Target) {
  const isPrivate = target.kind === 'private';
  const disabled = Boolean(target.disabled || (isPrivate && !target.online));
  return `
    <article class="target-card">
      <div>
        <h2>${escapeHtml(target.name)}${isPrivate ? ' <span class="target-badge">私有终端</span>' : ''}</h2>
        <p>${escapeHtml(target.sshUsername)}@${escapeHtml(target.host)}:${target.port}</p>
        ${isPrivate ? `<p class="target-status ${target.online ? 'online' : 'offline'}">${target.online ? 'Agent 在线' : 'Agent 离线'}</p>` : ''}
      </div>
      <button class="button primary" type="button" data-connect-target="${target.id}" data-target-kind="${escapeHtml(target.kind || 'ssh')}" ${disabled ? 'disabled' : ''}>打开终端</button>
    </article>
  `;
}

async function renderTerminal(ticket: string) {
  if (!ticket) {
    renderError(new Error('缺少终端票据'));
    return;
  }
  const payload = await api<{ target: Target; expiresAt: string }>(`terminal/tickets/${encodeURIComponent(ticket)}`);
  setView(shell(`
    <section id="terminalShell" class="terminal-shell">
      <aside class="connect-panel">
        <button id="connectPanelExpand" class="connect-expand-button" type="button" title="展开连接面板">连接</button>
        <div class="connect-panel-content">
          <div class="connect-panel-header">
            <div>
              <p class="eyebrow">SSH session</p>
              <h1>${escapeHtml(payload.target.name)}</h1>
              <p class="muted">${escapeHtml(payload.target.sshUsername)}@${escapeHtml(payload.target.host)}:${payload.target.port}</p>
            </div>
            <button id="connectPanelCollapse" class="button small" type="button">收起</button>
          </div>
          <form id="connectForm">
            <label>
              <span>认证方式</span>
              <select name="method" id="authMethod">
                <option value="password">密码</option>
                <option value="privateKey">私钥</option>
              </select>
            </label>
            <label data-auth-field="password">
              <span>SSH 密码</span>
              <input name="password" type="password" autocomplete="off" />
            </label>
            <label data-auth-field="privateKey" hidden>
              <span>SSH 私钥</span>
              <textarea name="privateKey" rows="7" spellcheck="false"></textarea>
            </label>
            <label data-auth-field="privateKey" hidden>
              <span>私钥 passphrase</span>
              <input name="passphrase" type="password" autocomplete="off" />
            </label>
            <button class="button primary" type="submit">连接</button>
            <a class="button ghost" href="${BASE_PATH}">返回</a>
            <div id="message" class="message"></div>
          </form>
        </div>
      </aside>
      <div id="terminalResizeHandle" class="terminal-resize-handle" role="separator" aria-label="调整终端宽度" aria-orientation="vertical" title="拖拽调整终端区域，双击恢复默认"></div>
      <section id="terminalPanel" class="terminal-panel">
        <div class="terminal-panel-header">
          <div>
            <strong>Terminal</strong>
            <small>SSH WebSocket session</small>
          </div>
          <div class="terminal-actions">
            <select id="terminalKeyProfile" class="terminal-key-profile" title="特殊键类型">
              <option value="auto">自动</option>
              <option value="macos">macOS</option>
              <option value="windows">Windows</option>
              <option value="linux">Linux</option>
            </select>
            <button id="terminalKeySettingsButton" class="button small ghost" type="button" aria-expanded="false">按键</button>
            <button id="terminalFitButton" class="button small ghost" type="button">适配</button>
            <button id="terminalFullscreenButton" class="button small" type="button">全屏</button>
          </div>
        </div>
        <div id="terminalKeySettings" class="terminal-key-settings" hidden>
          <div class="terminal-key-settings-head">
            <strong>特殊键</strong>
            <button id="terminalKeyResetButton" class="button small ghost" type="button">恢复默认</button>
          </div>
          <div id="terminalKeyOrderList" class="terminal-key-order-list"></div>
        </div>
        <div id="terminal"></div>
        <div id="mobileTerminalToolbar" class="mobile-terminal-toolbar" aria-label="移动端终端辅助按键">
          <div id="mobileTerminalToolbarRow" class="mobile-terminal-toolbar-row">
            ${terminalKeyButtons(loadTerminalKeyConfig())}
          </div>
        </div>
      </section>
      <aside id="terminalTextPanel" class="terminal-text-panel">
        <button id="terminalTextPanelExpand" class="terminal-text-expand-button" type="button" title="展开文本发送区">文本</button>
        <div class="terminal-text-panel-content">
          <div class="terminal-text-panel-header">
            <div>
              <strong>文本输入</strong>
              <small>发送到当前光标</small>
            </div>
            <button id="terminalTextPanelCollapse" class="button small" type="button">收起</button>
          </div>
          <textarea id="terminalTextBuffer" spellcheck="false" placeholder="输入需要键入终端的内容"></textarea>
          <div class="terminal-text-actions">
            <button id="terminalTextSend" class="button primary small" type="button">发送</button>
            <button id="terminalTextSendEnter" class="button small" type="button">发送并回车</button>
            <button id="terminalTextClear" class="button ghost small" type="button">清空</button>
          </div>
        </div>
      </aside>
    </section>
  `));

  document.body.classList.add('terminal-page');
  setupTerminalLayoutControls();
  setupTerminalViewportControls();
  setupTerminalKeyControls();
  setupTerminalMobileToolbar();
  setupTerminalTextControls();

  const methodSelect = document.querySelector<HTMLSelectElement>('#authMethod');
  methodSelect?.addEventListener('change', () => updateAuthFields(methodSelect.value));

  document.querySelector<HTMLFormElement>('#connectForm')?.addEventListener('submit', (event) => {
    event.preventDefault();
    if (Date.now() >= Date.parse(payload.expiresAt)) {
      showMessage('终端票据已过期，请返回目标列表重新打开终端。', 'error');
      return;
    }
    const form = new FormData(event.currentTarget);
    startTerminal(ticket, {
      method: String(form.get('method') || 'password'),
      password: String(form.get('password') || ''),
      privateKey: String(form.get('privateKey') || ''),
      passphrase: String(form.get('passphrase') || '')
    });
  });
}

function terminalKeyButtons(config: TerminalKeyConfig) {
  return terminalToolbarItems(config).map((item) => {
    if (item.type === 'modifier') {
      const action = TERMINAL_MODIFIER_ACTIONS.find((candidate) => candidate.id === item.id);
      if (!action) return '';
      return `
        <button class="terminal-key modifier" type="button" data-terminal-modifier="${action.id}" aria-pressed="${terminalModifierState.has(action.id)}" title="${escapeHtml(terminalModifierTitle(action, config))}">${escapeHtml(terminalModifierLabel(action, config))}</button>
      `;
    }
    if (item.type === 'utility') {
      const action = TERMINAL_UTILITY_ACTIONS.find((candidate) => candidate.id === item.id);
      if (!action) return '';
      return `
        <button class="terminal-key${action.wide ? ' wide' : ''}" type="button" data-terminal-utility="${action.id}" title="${escapeHtml(action.title)}">${escapeHtml(action.label)}</button>
      `;
    }
    const action = TERMINAL_KEY_ACTIONS.find((candidate) => candidate.id === item.id);
    if (!action) return '';
    return `
      <button class="terminal-key${action.wide ? ' wide' : ''}" type="button" data-terminal-key="${action.id}" title="${escapeHtml(action.title)}">${escapeHtml(action.label)}</button>
    `;
  }).join('');
}

function terminalKeySettingsRows(config: TerminalKeyConfig) {
  const hidden = new Set(config.hidden);
  return config.order.map((key, index) => `
    <div class="terminal-key-config-row" data-terminal-item="${escapeHtml(key)}">
      <label class="terminal-key-visible">
        <input type="checkbox" data-terminal-key-visible="${escapeHtml(key)}" ${hidden.has(key) ? '' : 'checked'} />
        <span>${escapeHtml(terminalToolbarItemLabel(key, config))}</span>
      </label>
      <div class="terminal-key-order-actions">
        <button class="button small ghost" type="button" data-terminal-key-move="up" ${index === 0 ? 'disabled' : ''}>↑</button>
        <button class="button small ghost" type="button" data-terminal-key-move="down" ${index === config.order.length - 1 ? 'disabled' : ''}>↓</button>
      </div>
    </div>
  `).join('');
}

function renderTerminalKeyControls(config = loadTerminalKeyConfig()) {
  const normalized = normalizeTerminalKeyConfig(config);
  const profileSelect = document.querySelector<HTMLSelectElement>('#terminalKeyProfile');
  const toolbarRow = document.querySelector<HTMLElement>('#mobileTerminalToolbarRow');
  const orderList = document.querySelector<HTMLElement>('#terminalKeyOrderList');

  if (profileSelect) profileSelect.value = normalized.profile;
  if (toolbarRow) toolbarRow.innerHTML = terminalKeyButtons(normalized);
  if (orderList) orderList.innerHTML = terminalKeySettingsRows(normalized);
  updateTerminalModifierButtons(toolbarRow || document);
  scheduleTerminalFit();
}

function isCompactTerminalLayout() {
  return window.matchMedia('(max-width: 880px)').matches;
}

function setTerminalConnectPanelCollapsed(collapsed: boolean) {
  const shell = document.querySelector<HTMLElement>('#terminalShell');
  const collapseButton = document.querySelector<HTMLButtonElement>('#connectPanelCollapse');
  const expandButton = document.querySelector<HTMLButtonElement>('#connectPanelExpand');
  if (!shell) return;
  shell.classList.toggle('connect-collapsed', collapsed);
  collapseButton?.setAttribute('aria-expanded', String(!collapsed));
  expandButton?.setAttribute('aria-expanded', String(!collapsed));
  scheduleTerminalFit();
}

function setTerminalTextPanelCollapsed(collapsed: boolean) {
  const shell = document.querySelector<HTMLElement>('#terminalShell');
  const collapseButton = document.querySelector<HTMLButtonElement>('#terminalTextPanelCollapse');
  const expandButton = document.querySelector<HTMLButtonElement>('#terminalTextPanelExpand');
  if (!shell) return;
  shell.classList.toggle('text-collapsed', collapsed);
  collapseButton?.setAttribute('aria-expanded', String(!collapsed));
  expandButton?.setAttribute('aria-expanded', String(!collapsed));
  scheduleTerminalFit();
}

function setTerminalSessionActive(active: boolean) {
  document.querySelector<HTMLElement>('#terminalShell')?.classList.toggle('terminal-session-active', active);
}

function setupTerminalKeyControls() {
  const settings = document.querySelector<HTMLElement>('#terminalKeySettings');
  const settingsButton = document.querySelector<HTMLButtonElement>('#terminalKeySettingsButton');
  const profileSelect = document.querySelector<HTMLSelectElement>('#terminalKeyProfile');
  const resetButton = document.querySelector<HTMLButtonElement>('#terminalKeyResetButton');
  const orderList = document.querySelector<HTMLElement>('#terminalKeyOrderList');

  renderTerminalKeyControls();

  settingsButton?.addEventListener('click', () => {
    if (!settings) return;
    const hidden = !settings.hidden;
    settings.hidden = hidden;
    settingsButton.setAttribute('aria-expanded', String(!hidden));
    scheduleTerminalFit();
  });

  profileSelect?.addEventListener('change', () => {
    const config = loadTerminalKeyConfig();
    config.profile = isTerminalKeyProfile(profileSelect.value) ? profileSelect.value : 'auto';
    saveTerminalKeyConfig(config);
    renderTerminalKeyControls(config);
  });

  resetButton?.addEventListener('click', () => {
    const config = normalizeTerminalKeyConfig();
    saveTerminalKeyConfig(config);
    renderTerminalKeyControls(config);
  });

  orderList?.addEventListener('click', (event) => {
    const button = (event.target as HTMLElement | null)?.closest<HTMLButtonElement>('[data-terminal-key-move]');
    const row = button?.closest<HTMLElement>('[data-terminal-item]');
    if (!button || !row?.dataset.terminalItem) return;

    const config = loadTerminalKeyConfig();
    const currentIndex = config.order.indexOf(row.dataset.terminalItem);
    const offset = button.dataset.terminalKeyMove === 'up' ? -1 : 1;
    const nextIndex = currentIndex + offset;
    if (currentIndex < 0 || nextIndex < 0 || nextIndex >= config.order.length) return;

    const [item] = config.order.splice(currentIndex, 1);
    config.order.splice(nextIndex, 0, item);
    saveTerminalKeyConfig(config);
    renderTerminalKeyControls(config);
  });

  orderList?.addEventListener('change', (event) => {
    const checkbox = (event.target as HTMLElement | null)?.closest<HTMLInputElement>('[data-terminal-key-visible]');
    if (!checkbox?.dataset.terminalKeyVisible) return;

    const config = loadTerminalKeyConfig();
    const hidden = new Set(config.hidden);
    if (checkbox.checked) {
      hidden.delete(checkbox.dataset.terminalKeyVisible);
    } else {
      hidden.add(checkbox.dataset.terminalKeyVisible);
    }
    config.hidden = Array.from(hidden);
    saveTerminalKeyConfig(config);
    renderTerminalKeyControls(config);
  });
}

function updateAuthFields(method: string) {
  for (const element of document.querySelectorAll<HTMLElement>('[data-auth-field]')) {
    element.hidden = element.dataset.authField !== method;
  }
}

function startTerminal(ticket: string, auth: Record<string, string>) {
  const terminalNode = document.querySelector<HTMLDivElement>('#terminal');
  const terminalPanel = document.querySelector<HTMLDivElement>('#terminalPanel');
  const form = document.querySelector<HTMLFormElement>('#connectForm');
  if (!terminalNode || !form) return;

  form.querySelectorAll('input, textarea, select, button').forEach((node) => {
    (node as HTMLInputElement | HTMLButtonElement | HTMLTextAreaElement | HTMLSelectElement).disabled = true;
  });

  setTerminalSessionActive(true);
  if (isCompactTerminalLayout()) {
    setTerminalConnectPanelCollapsed(true);
    setTerminalTextPanelCollapsed(true);
  }

  const term = new Terminal({
    cursorBlink: true,
    convertEol: true,
    fontFamily: '"SFMono-Regular", Consolas, "Liberation Mono", monospace',
    fontSize: 13,
    theme: {
      background: '#101827',
      foreground: '#d6e0f0',
      cursor: '#ffffff'
    }
  });
  const fitAddon = new FitAddon();
  term.loadAddon(fitAddon);
  term.open(terminalNode);
  configureTerminalHelperTextarea();
  term.writeln('Connecting...');
  terminalNode.addEventListener('pointerdown', () => {
    term.focus();
    configureTerminalHelperTextarea();
  });

  const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws = new WebSocket(`${protocol}//${location.host}${BASE_PATH}ws/terminal?ticket=${encodeURIComponent(ticket)}`);
  let socketOpened = false;
  let terminalReady = false;

  const fitAndSendSize = () => {
    fitAddon.fit();
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: 'resize', cols: term.cols, rows: term.rows }));
    }
  };

  activeTerminalFit = fitAndSendSize;
  activeTerminalFocus = () => {
    term.focus();
    configureTerminalHelperTextarea();
  };
  activeTerminalBlur = () => document.querySelector<HTMLElement>('#terminal .xterm-helper-textarea')?.blur();
  scheduleTerminalFit();
  if (terminalPanel && 'ResizeObserver' in window) {
    const resizeObserver = new ResizeObserver(() => scheduleTerminalFit());
    resizeObserver.observe(terminalPanel);
    resizeObserver.observe(terminalNode);
  }

  ws.addEventListener('open', () => {
    socketOpened = true;
    fitAndSendSize();
    const dimensions = fitAddon.proposeDimensions();
    ws.send(JSON.stringify({
      type: 'connect',
      cols: dimensions?.cols || term.cols,
      rows: dimensions?.rows || term.rows,
      auth
    }));
  });

  ws.addEventListener('message', (event) => {
    const message = JSON.parse(String(event.data));
    if (message.type === 'data') term.write(message.data);
    if (message.type === 'ready') {
      terminalReady = true;
      showMessage('SSH 终端已连接');
      term.clear();
      activeTerminalFocus?.();
      if (isCompactTerminalLayout()) {
        setTerminalConnectPanelCollapsed(true);
        setTerminalTextPanelCollapsed(true);
      }
    }
    if (message.type === 'error') {
      showMessage(message.message, 'error');
      term.writeln(`\r\n${message.message}`);
      if (isCompactTerminalLayout()) setTerminalConnectPanelCollapsed(false);
    }
    if (message.type === 'closed') term.writeln('\r\nSession closed.');
  });

  ws.addEventListener('error', () => {
    const message = socketOpened
      ? 'SSH 终端连接异常，请检查 SSH 凭据或目标主机状态。'
      : 'WebSocket 连接失败，请检查登录状态、目标权限或重新打开终端。';
    showMessage(message, 'error');
    term.writeln(`\r\n${message}`);
    if (isCompactTerminalLayout()) setTerminalConnectPanelCollapsed(false);
  });

  ws.addEventListener('close', () => {
    if (!terminalReady) {
      showMessage('终端未能建立连接，请返回目标列表重新打开终端。', 'error');
      if (isCompactTerminalLayout()) setTerminalConnectPanelCollapsed(false);
    }
    term.writeln('\r\nDisconnected.');
  });

  term.onData((data) => {
    sendTerminalData(applyTerminalModifiers(data));
  });

  activeTerminalInput = sendTerminalData;

  window.addEventListener('resize', () => {
    fitAndSendSize();
  });

  function sendTerminalData(data: string) {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: 'data', data }));
    }
  }
}

function setupTerminalMobileToolbar() {
  const toolbar = document.querySelector<HTMLElement>('#mobileTerminalToolbar');
  if (!toolbar) return;

  toolbar.addEventListener('pointerdown', (event) => {
    const target = event.target as HTMLElement | null;
    if (!target?.closest('button')) return;
    event.preventDefault();
  });

  toolbar.addEventListener('click', (event) => {
    const button = (event.target as HTMLElement | null)?.closest<HTMLButtonElement>('button');
    if (!button || !toolbar.contains(button)) return;

    if (button.dataset.terminalKey) {
      const action = TERMINAL_KEY_ACTIONS.find((item) => item.id === button.dataset.terminalKey);
      if (!action) return;
      const data = action.useModifiers === false ? consumeTerminalModifiers(action.data) : applyTerminalModifiers(action.data);
      activeTerminalInput?.(data);
      activeTerminalFocus?.();
      return;
    }

    if (button.dataset.terminalModifier) {
      const modifier = button.dataset.terminalModifier as TerminalModifier | undefined;
      if (!modifier) return;
      toggleTerminalModifier(modifier, toolbar);
      activeTerminalFocus?.();
      return;
    }

    if (button.dataset.terminalUtility === 'keyboard') {
      const terminalElement = document.querySelector<HTMLElement>('#terminal .xterm');
      if (terminalElement && document.activeElement && terminalElement.contains(document.activeElement)) {
        activeTerminalBlur?.();
        return;
      }
      activeTerminalFocus?.();
    }
  });
}

function setupTerminalTextControls() {
  const collapseButton = document.querySelector<HTMLButtonElement>('#terminalTextPanelCollapse');
  const expandButton = document.querySelector<HTMLButtonElement>('#terminalTextPanelExpand');
  const textarea = document.querySelector<HTMLTextAreaElement>('#terminalTextBuffer');
  const sendButton = document.querySelector<HTMLButtonElement>('#terminalTextSend');
  const sendEnterButton = document.querySelector<HTMLButtonElement>('#terminalTextSendEnter');
  const clearButton = document.querySelector<HTMLButtonElement>('#terminalTextClear');
  if (!textarea) return;

  if (isCompactTerminalLayout()) setTerminalTextPanelCollapsed(true);

  collapseButton?.addEventListener('click', () => setTerminalTextPanelCollapsed(true));
  expandButton?.addEventListener('click', () => setTerminalTextPanelCollapsed(false));

  sendButton?.addEventListener('click', () => {
    sendTerminalText(textarea.value, false);
  });

  sendEnterButton?.addEventListener('click', () => {
    sendTerminalText(textarea.value, true);
  });

  clearButton?.addEventListener('click', () => {
    textarea.value = '';
    textarea.focus();
  });
}

function sendTerminalText(value: string, appendEnter: boolean) {
  if (!value && !appendEnter) return;
  if (!activeTerminalInput) {
    showMessage('请先连接 SSH 终端。', 'error');
    return;
  }

  const data = normalizeTerminalText(value) + (appendEnter ? '\r' : '');
  sendTerminalInputInChunks(data);
  activeTerminalFocus?.();
  if (isCompactTerminalLayout()) setTerminalTextPanelCollapsed(true);
  showMessage('文本已发送到终端');
}

function normalizeTerminalText(value: string) {
  return value
    .replace(/\r\n/g, '\n')
    .replace(/\r/g, '\n')
    .replace(/\n/g, '\r');
}

function configureTerminalHelperTextarea() {
  const helper = document.querySelector<HTMLTextAreaElement>('#terminal .xterm-helper-textarea');
  if (!helper) return;
  helper.autocomplete = 'off';
  helper.autocapitalize = 'none';
  helper.spellcheck = false;
  helper.setAttribute('autocorrect', 'off');
}

function sendTerminalInputInChunks(data: string) {
  const chunkSize = 4096;
  for (let index = 0; index < data.length; index += chunkSize) {
    const chunk = data.slice(index, index + chunkSize);
    window.setTimeout(() => activeTerminalInput?.(chunk), Math.floor(index / chunkSize) * 8);
  }
}

function toggleTerminalModifier(modifier: TerminalModifier, toolbar?: ParentNode | null) {
  if (terminalModifierState.has(modifier)) {
    terminalModifierState.delete(modifier);
  } else {
    terminalModifierState.add(modifier);
  }
  updateTerminalModifierButtons(toolbar);
}

function clearTerminalModifiers(toolbar?: ParentNode | null) {
  if (!terminalModifierState.size) return;
  terminalModifierState.clear();
  updateTerminalModifierButtons(toolbar);
}

function updateTerminalModifierButtons(toolbar: ParentNode | null = document) {
  const root = toolbar || document;
  for (const button of root.querySelectorAll<HTMLButtonElement>('[data-terminal-modifier]')) {
    const active = terminalModifierState.has(button.dataset.terminalModifier as TerminalModifier);
    button.classList.toggle('active', active);
    button.setAttribute('aria-pressed', String(active));
  }
}

function consumeTerminalModifiers(data: string) {
  clearTerminalModifiers();
  return data;
}

function applyTerminalModifiers(data: string) {
  if (!terminalModifierState.size) return data;

  const modified = modifiedTerminalData(data);
  clearTerminalModifiers();
  return modified;
}

function modifiedTerminalData(data: string) {
  const hasAlt = terminalModifierState.has('alt') || terminalModifierState.has('meta');
  const hasCtrl = terminalModifierState.has('ctrl');
  const hasShift = terminalModifierState.has('shift');
  const modifierCode = terminalModifierCode();

  const arrow = TERMINAL_ARROW_SEQUENCES[data];
  if (arrow) return `\x1b[1;${modifierCode}${arrow}`;

  const homeEnd = TERMINAL_HOME_END_SEQUENCES[data];
  if (homeEnd) return `\x1b[1;${modifierCode}${homeEnd}`;

  const ss3 = TERMINAL_SS3_SEQUENCES[data];
  if (ss3) return `\x1b[1;${modifierCode}${ss3}`;

  const tilde = TERMINAL_TILDE_SEQUENCES[data];
  if (tilde) return `\x1b[${tilde};${modifierCode}~`;

  if (data.length === 1) {
    let output = hasShift ? shiftedTerminalCharacter(data) : data;
    if (hasCtrl) output = controlTerminalCharacter(output) || output;
    if (hasAlt) output = `\x1b${output}`;
    return output;
  }

  return hasAlt ? `\x1b${data}` : data;
}

function terminalModifierCode() {
  return 1
    + (terminalModifierState.has('shift') ? 1 : 0)
    + (terminalModifierState.has('alt') || terminalModifierState.has('meta') ? 2 : 0)
    + (terminalModifierState.has('ctrl') ? 4 : 0);
}

function shiftedTerminalCharacter(data: string) {
  if (data >= 'a' && data <= 'z') return data.toUpperCase();
  return SHIFTED_TERMINAL_CHARS[data] || data;
}

function controlTerminalCharacter(data: string) {
  const letter = data.toUpperCase();
  if (letter >= 'A' && letter <= 'Z') {
    return String.fromCharCode(letter.charCodeAt(0) - 64);
  }
  if (data === ' ' || data === '@' || data === '`') return '\x00';
  if (data === '[') return '\x1b';
  if (data === '\\') return '\x1c';
  if (data === ']') return '\x1d';
  if (data === '^') return '\x1e';
  if (data === '_' || data === '/') return '\x1f';
  if (data === '?') return '\x7f';
  return '';
}

function setupTerminalViewportControls() {
  const updateViewportHeight = () => {
    const height = window.visualViewport?.height || window.innerHeight;
    document.documentElement.style.setProperty('--terminal-viewport-height', `${height}px`);
    scheduleTerminalFit();
  };

  updateViewportHeight();
  window.visualViewport?.addEventListener('resize', updateViewportHeight);
  window.visualViewport?.addEventListener('scroll', updateViewportHeight);
  window.addEventListener('orientationchange', updateViewportHeight);

  terminalViewportCleanup = () => {
    window.visualViewport?.removeEventListener('resize', updateViewportHeight);
    window.visualViewport?.removeEventListener('scroll', updateViewportHeight);
    window.removeEventListener('orientationchange', updateViewportHeight);
  };
}

function setupTerminalLayoutControls() {
  const shell = document.querySelector<HTMLElement>('#terminalShell');
  const terminalPanel = document.querySelector<HTMLElement>('#terminalPanel');
  const collapseButton = document.querySelector<HTMLButtonElement>('#connectPanelCollapse');
  const expandButton = document.querySelector<HTMLButtonElement>('#connectPanelExpand');
  const handle = document.querySelector<HTMLElement>('#terminalResizeHandle');
  const fitButton = document.querySelector<HTMLButtonElement>('#terminalFitButton');
  const fullscreenButton = document.querySelector<HTMLButtonElement>('#terminalFullscreenButton');
  if (!shell || !terminalPanel) return;

  const setCollapsed = (collapsed: boolean) => {
    shell.classList.toggle('connect-collapsed', collapsed);
    collapseButton?.setAttribute('aria-expanded', String(!collapsed));
    expandButton?.setAttribute('aria-expanded', String(!collapsed));
    scheduleTerminalFit();
  };

  collapseButton?.addEventListener('click', () => setCollapsed(true));
  expandButton?.addEventListener('click', () => setCollapsed(false));
  fitButton?.addEventListener('click', () => scheduleTerminalFit());

  const setImmersive = (enabled: boolean) => {
    terminalPanel.classList.toggle('terminal-immersive', enabled);
    document.body.classList.toggle('terminal-immersive-active', enabled);
    if (fullscreenButton) fullscreenButton.textContent = enabled ? '退出全屏' : '全屏';
    if (enabled) window.scrollTo(0, 0);
    scheduleTerminalFit();
  };

  fullscreenButton?.addEventListener('click', async () => {
    if (document.fullscreenElement === terminalPanel) {
      try {
        await document.exitFullscreen();
      } catch (error) {
        showMessage((error as Error).message, 'error');
      }
      return;
    }
    if (terminalPanel.classList.contains('terminal-immersive')) {
      setImmersive(false);
      return;
    }
    try {
      if (document.fullscreenEnabled && terminalPanel.requestFullscreen) {
        await terminalPanel.requestFullscreen();
      } else {
        setImmersive(true);
      }
      scheduleTerminalFit();
    } catch (error) {
      setImmersive(true);
    }
  });

  document.addEventListener('fullscreenchange', () => {
    if (document.fullscreenElement === terminalPanel) {
      setImmersive(false);
    }
    if (fullscreenButton) {
      fullscreenButton.textContent =
        document.fullscreenElement === terminalPanel || terminalPanel.classList.contains('terminal-immersive')
          ? '退出全屏'
          : '全屏';
    }
    scheduleTerminalFit();
  });

  if (!handle) return;

  const setConnectWidth = (clientX: number) => {
    const rect = shell.getBoundingClientRect();
    const textReserve = shell.classList.contains('text-collapsed') ? 70 : 330;
    const max = Math.max(280, rect.width - textReserve - 420);
    const width = clamp(clientX - rect.left, 240, Math.min(560, max));
    shell.style.setProperty('--connect-panel-width', `${width}px`);
    scheduleTerminalFit();
  };

  handle.addEventListener('pointerdown', (event) => {
    event.preventDefault();
    if (shell.classList.contains('connect-collapsed')) setCollapsed(false);
    handle.setPointerCapture(event.pointerId);
    handle.classList.add('dragging');
    setConnectWidth(event.clientX);
  });

  handle.addEventListener('pointermove', (event) => {
    if (!handle.classList.contains('dragging')) return;
    setConnectWidth(event.clientX);
  });

  const stopDrag = (event: PointerEvent) => {
    if (handle.hasPointerCapture(event.pointerId)) handle.releasePointerCapture(event.pointerId);
    handle.classList.remove('dragging');
  };

  handle.addEventListener('pointerup', stopDrag);
  handle.addEventListener('pointercancel', stopDrag);
  handle.addEventListener('dblclick', () => {
    shell.style.removeProperty('--connect-panel-width');
    setCollapsed(false);
    scheduleTerminalFit();
  });
}

function scheduleTerminalFit() {
  window.requestAnimationFrame(() => {
    activeTerminalFit?.();
    window.setTimeout(() => activeTerminalFit?.(), 140);
  });
}

function clamp(value: number, min: number, max: number) {
  return Math.min(max, Math.max(min, value));
}

async function renderAdmin() {
  const me = await api<{ authenticated: boolean; user?: User; features?: { privateRelay?: boolean } }>('me');
  if (!me.authenticated || me.user?.role !== 'admin') {
    setView(shell(`
      <section class="panel">
        <h1>需要管理员登录</h1>
        <p class="muted">请先通过管理员专属访问链接完成密码和 TOTP 双因子登录。</p>
      </section>
    `));
    return;
  }

  const privateRelayEnabled = Boolean(me.features?.privateRelay);
  const [{ users, links }, { targets }, privateEndpointsPayload] = await Promise.all([
    api<{ users: User[]; links: Array<Record<string, unknown>> }>('admin/users'),
    api<{ targets: Target[] }>('admin/targets'),
    privateRelayEnabled
      ? api<{ endpoints: Target[] }>('admin/private-endpoints')
      : Promise.resolve({ endpoints: [] as Target[] })
  ]);
  const privateEndpoints = privateEndpointsPayload.endpoints;

  setView(shell(`
    <section class="workspace-head">
      <div>
        <p class="eyebrow">Admin</p>
        <h1>TermLens 管理后台</h1>
        <p class="muted">管理用户、SSH 目标、权限和随机访问链接。</p>
      </div>
      <a class="button" href="${BASE_PATH}">返回首页</a>
    </section>

    <section class="admin-grid">
      <form id="createUserForm" class="panel">
        <h2>新增用户</h2>
        <label><span>用户名</span><input name="username" required /></label>
        <label><span>显示名</span><input name="displayName" /></label>
        <label><span>角色</span><select name="role"><option value="user">user</option><option value="admin">admin</option></select></label>
        <label><span>初始密码</span><input name="password" type="password" minlength="12" required /></label>
        <button class="button primary" type="submit">创建用户并生成访问链接</button>
      </form>

      <form id="createTargetForm" class="panel">
        <h2>新增 SSH 目标</h2>
        <label><span>名称</span><input name="name" required /></label>
        <label><span>Host</span><input name="host" required /></label>
        <label><span>端口</span><input name="port" type="number" value="22" min="1" max="65535" required /></label>
        <label><span>SSH 用户</span><input name="sshUsername" required /></label>
        <button class="button primary" type="submit">创建目标</button>
      </form>

      ${privateRelayEnabled ? `
        <form id="createPrivateEndpointForm" class="panel">
          <h2>新增私有终端</h2>
          <p class="muted">用于本地笔记本或 NAT 后电脑。默认只允许 Agent 转发本机 SSH。</p>
          <label><span>名称</span><input name="name" required /></label>
          <label><span>本地 Host</span><input name="localHost" value="127.0.0.1" required /></label>
          <label><span>本地端口</span><input name="localPort" type="number" value="22" min="1" max="65535" required /></label>
          <label><span>SSH 用户</span><input name="sshUsername" required /></label>
          <button class="button primary" type="submit">创建并生成 Agent 注册命令</button>
        </form>
      ` : ''}
    </section>

    <section class="panel">
      <h2>用户</h2>
      <div class="table-wrap">
        <table>
          <thead><tr><th>ID</th><th>用户</th><th>角色</th><th>2FA</th><th>状态</th><th>操作</th></tr></thead>
          <tbody>
            ${users.map((user) => `
              <tr>
                <td>${user.id}</td>
                <td><strong>${escapeHtml(user.username)}</strong><br><span>${escapeHtml(user.displayName)}</span></td>
                <td>${escapeHtml(user.role)}</td>
                <td>${user.totpEnabled ? '已启用' : '待设置'}</td>
                <td>${user.disabled ? '禁用' : '启用'}</td>
                <td class="action-cell">
                  <button class="button small" data-link-user="${user.id}" type="button">生成链接</button>
                  <button class="button small" data-reset-totp="${user.id}" type="button">重置 2FA</button>
                  <button class="button small" data-toggle-user="${user.id}" data-disabled="${user.disabled ? '0' : '1'}" type="button">${user.disabled ? '启用' : '禁用'}</button>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </section>

    <section class="panel">
      <h2>SSH 目标</h2>
      <div class="table-wrap">
        <table>
          <thead><tr><th>ID</th><th>名称</th><th>地址</th><th>状态</th><th>操作</th></tr></thead>
          <tbody>
            ${targets.map((target) => `
              <tr>
                <td>${target.id}</td>
                <td>${escapeHtml(target.name)}</td>
                <td>${escapeHtml(target.sshUsername)}@${escapeHtml(target.host)}:${target.port}</td>
                <td>${target.disabled ? '禁用' : '启用'}</td>
                <td><button class="button small" data-toggle-target="${target.id}" data-disabled="${target.disabled ? '0' : '1'}" type="button">${target.disabled ? '启用' : '禁用'}</button></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </section>

    ${privateRelayEnabled ? `
      <section class="panel">
        <h2>私有终端</h2>
        <div class="table-wrap">
          <table>
            <thead><tr><th>ID</th><th>名称</th><th>本地地址</th><th>Agent</th><th>状态</th><th>操作</th></tr></thead>
            <tbody>
              ${privateEndpoints.map((endpoint) => `
                <tr>
                  <td>${endpoint.id}</td>
                  <td>${escapeHtml(endpoint.name)}</td>
                  <td>${escapeHtml(endpoint.sshUsername)}@${escapeHtml(endpoint.host)}:${endpoint.port}</td>
                  <td>${endpoint.agentEnrolled ? '已注册' : '未注册'}${endpoint.lastSeenAt ? `<br><span>${escapeHtml(endpoint.lastSeenAt)}</span>` : ''}</td>
                  <td>${endpoint.disabled ? '禁用' : endpoint.online ? '在线' : '离线'}</td>
                  <td class="action-cell">
                    <button class="button small" data-private-enrollment="${endpoint.id}" type="button">注册命令</button>
                    <button class="button small" data-toggle-private-endpoint="${endpoint.id}" data-disabled="${endpoint.disabled ? '0' : '1'}" type="button">${endpoint.disabled ? '启用' : '禁用'}</button>
                  </td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </section>
    ` : ''}

    <section class="panel">
      <h2>用户目标权限</h2>
      <form id="permissionForm" class="permission-form">
        <label>
          <span>用户</span>
          <select name="userId">
            ${users.map((user) => `<option value="${user.id}">${escapeHtml(user.username)}</option>`).join('')}
          </select>
        </label>
        <div class="checkbox-list">
          ${targets.map((target) => `
            <label class="checkbox-row">
              <input type="checkbox" name="targetIds" value="${target.id}" />
              <span>${escapeHtml(target.name)} (${escapeHtml(target.sshUsername)}@${escapeHtml(target.host)}:${target.port})</span>
            </label>
          `).join('')}
        </div>
        <button class="button primary" type="submit">保存权限</button>
      </form>
    </section>

    ${privateRelayEnabled ? `
      <section class="panel">
        <h2>用户私有终端权限</h2>
        <form id="privatePermissionForm" class="permission-form">
          <label>
            <span>用户</span>
            <select name="userId">
              ${users.map((user) => `<option value="${user.id}">${escapeHtml(user.username)}</option>`).join('')}
            </select>
          </label>
          <div class="checkbox-list">
            ${privateEndpoints.map((endpoint) => `
              <label class="checkbox-row">
                <input type="checkbox" name="endpointIds" value="${endpoint.id}" />
                <span>${escapeHtml(endpoint.name)} (${escapeHtml(endpoint.sshUsername)}@${escapeHtml(endpoint.host)}:${endpoint.port})</span>
              </label>
            `).join('') || '<div class="empty">暂无私有终端。</div>'}
          </div>
          <button class="button primary" type="submit">保存私有终端权限</button>
        </form>
      </section>
    ` : ''}

    <section class="panel">
      <h2>访问链接记录</h2>
      <div class="table-wrap">
        <table>
          <thead><tr><th>ID</th><th>用户 ID</th><th>标签</th><th>使用次数</th><th>状态</th><th>创建时间</th></tr></thead>
          <tbody>
            ${links.map((link) => `
              <tr>
                <td>${escapeHtml(link.id)}</td>
                <td>${escapeHtml(link.user_id)}</td>
                <td>${escapeHtml(link.label)}</td>
                <td>${escapeHtml(link.used_count)} / ${Number(link.max_uses) > 0 ? escapeHtml(link.max_uses) : '不限'}</td>
                <td>${link.disabled ? '禁用' : '启用'}</td>
                <td>${escapeHtml(link.created_at)}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </section>

    <div id="message" class="message"></div>
  `));

  bindAdminEvents();
  const selectedUser = document.querySelector<HTMLSelectElement>('#permissionForm select[name="userId"]');
  if (selectedUser) {
    selectedUser.addEventListener('change', () => loadPermissions(Number(selectedUser.value)));
    await loadPermissions(Number(selectedUser.value));
  }
  const selectedPrivateUser = document.querySelector<HTMLSelectElement>('#privatePermissionForm select[name="userId"]');
  if (selectedPrivateUser) {
    selectedPrivateUser.addEventListener('change', () => loadPrivatePermissions(Number(selectedPrivateUser.value)));
    await loadPrivatePermissions(Number(selectedPrivateUser.value));
  }
}

function bindAdminEvents() {
  document.querySelector<HTMLFormElement>('#createUserForm')?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      const result = await api<{ accessUrl: string }>('admin/users', {
        method: 'POST',
        json: Object.fromEntries(form.entries())
      });
      await renderAdmin();
      showAccessLinkActions(result.accessUrl, '用户已创建，访问链接');
    } catch (error) {
      showMessage((error as Error).message, 'error');
    }
  });

  document.querySelector<HTMLFormElement>('#createTargetForm')?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      await api('admin/targets', { method: 'POST', json: Object.fromEntries(form.entries()) });
      await renderAdmin();
    } catch (error) {
      showMessage((error as Error).message, 'error');
    }
  });

  document.querySelector<HTMLFormElement>('#createPrivateEndpointForm')?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      const result = await api<{ enrollment: PrivateEnrollment }>('admin/private-endpoints', {
        method: 'POST',
        json: Object.fromEntries(form.entries())
      });
      await renderAdmin();
      showPrivateEnrollmentActions(result.enrollment);
    } catch (error) {
      showMessage((error as Error).message, 'error');
    }
  });

  document.querySelector<HTMLFormElement>('#permissionForm')?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const userId = Number(form.get('userId'));
    const targetIds = form.getAll('targetIds').map(Number);
    try {
      await api(`admin/users/${userId}/permissions`, { method: 'PUT', json: { targetIds } });
      showMessage('权限已保存');
    } catch (error) {
      showMessage((error as Error).message, 'error');
    }
  });

  document.querySelector<HTMLFormElement>('#privatePermissionForm')?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const userId = Number(form.get('userId'));
    const endpointIds = form.getAll('endpointIds').map(Number);
    try {
      await api(`admin/users/${userId}/private-permissions`, { method: 'PUT', json: { endpointIds } });
      showMessage('私有终端权限已保存');
    } catch (error) {
      showMessage((error as Error).message, 'error');
    }
  });

  document.querySelectorAll<HTMLButtonElement>('[data-link-user]').forEach((button) => {
    button.addEventListener('click', async () => {
      try {
        const result = await api<{ accessUrl: string }>(`admin/users/${button.dataset.linkUser}/access-links`, {
          method: 'POST',
          json: { label: 'manual' }
        });
        showAccessLinkActions(result.accessUrl, '新访问链接');
      } catch (error) {
        showMessage((error as Error).message, 'error');
      }
    });
  });

  document.querySelectorAll<HTMLButtonElement>('[data-reset-totp]').forEach((button) => {
    button.addEventListener('click', async () => {
      await api(`admin/users/${button.dataset.resetTotp}/totp/reset`, { method: 'POST', json: {} });
      await renderAdmin();
    });
  });

  document.querySelectorAll<HTMLButtonElement>('[data-toggle-user]').forEach((button) => {
    button.addEventListener('click', async () => {
      await api(`admin/users/${button.dataset.toggleUser}/disabled`, {
        method: 'POST',
        json: { disabled: button.dataset.disabled === '1' }
      });
      await renderAdmin();
    });
  });

  document.querySelectorAll<HTMLButtonElement>('[data-toggle-target]').forEach((button) => {
    button.addEventListener('click', async () => {
      await api(`admin/targets/${button.dataset.toggleTarget}/disabled`, {
        method: 'POST',
        json: { disabled: button.dataset.disabled === '1' }
      });
      await renderAdmin();
    });
  });

  document.querySelectorAll<HTMLButtonElement>('[data-private-enrollment]').forEach((button) => {
    button.addEventListener('click', async () => {
      try {
        const result = await api<{ enrollment: PrivateEnrollment }>(
          `admin/private-endpoints/${button.dataset.privateEnrollment}/enrollment`,
          { method: 'POST', json: {} }
        );
        showPrivateEnrollmentActions(result.enrollment);
      } catch (error) {
        showMessage((error as Error).message, 'error');
      }
    });
  });

  document.querySelectorAll<HTMLButtonElement>('[data-toggle-private-endpoint]').forEach((button) => {
    button.addEventListener('click', async () => {
      await api(`admin/private-endpoints/${button.dataset.togglePrivateEndpoint}/disabled`, {
        method: 'POST',
        json: { disabled: button.dataset.disabled === '1' }
      });
      await renderAdmin();
    });
  });
}

async function loadPermissions(userId: number) {
  const payload = await api<{ targetIds: number[] }>(`admin/users/${userId}/permissions`);
  const allowed = new Set(payload.targetIds);
  document.querySelectorAll<HTMLInputElement>('#permissionForm input[name="targetIds"]').forEach((input) => {
    input.checked = allowed.has(Number(input.value));
  });
}

async function loadPrivatePermissions(userId: number) {
  const payload = await api<{ endpointIds: number[] }>(`admin/users/${userId}/private-permissions`);
  const allowed = new Set(payload.endpointIds);
  document.querySelectorAll<HTMLInputElement>('#privatePermissionForm input[name="endpointIds"]').forEach((input) => {
    input.checked = allowed.has(Number(input.value));
  });
}

function shell(content: string) {
  return `
    <main class="app-shell">
      <header class="topbar">
        <a class="brand" href="${BASE_PATH}">
          <span class="brand-mark">TL</span>
          <span><strong>TermLens</strong><small>WebSSH with 2FA</small></span>
        </a>
        <nav class="top-actions">
          <a href="${BASE_PATH}admin">管理后台</a>
          <a href="https://www.difflens.io/">DiffLens</a>
        </nav>
      </header>
      ${content}
    </main>
  `;
}

function renderError(error: unknown) {
  setView(shell(`
    <section class="panel">
      <h1>请求无法完成</h1>
      <p class="message error">${escapeHtml((error as Error).message || '未知错误')}</p>
      <a class="button" href="${BASE_PATH}">返回首页</a>
    </section>
  `));
}
