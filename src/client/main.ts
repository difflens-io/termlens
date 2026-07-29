import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import '@xterm/xterm/css/xterm.css';
import './styles.css';

const BASE_PATH = import.meta.env.BASE_URL;
const app = document.querySelector<HTMLDivElement>('#app');
let activeTerminalFit: (() => void) | null = null;
let activeTerminalInput: ((data: string) => void) | null = null;
let activeTerminalFocus: (() => void) | null = null;
let activeTerminalBlur: (() => void) | null = null;
let terminalViewportCleanup: (() => void) | null = null;

if (!app) throw new Error('Missing #app root');

type ApiOptions = RequestInit & { json?: unknown };

interface Target {
  id: number;
  name: string;
  host: string;
  port: number;
  sshUsername: string;
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

interface TerminalKeyAction {
  id: string;
  label: string;
  data: string;
  title: string;
  wide?: boolean;
}

const TERMINAL_KEY_ACTIONS: TerminalKeyAction[] = [
  { id: 'esc', label: 'Esc', data: '\x1b', title: 'Escape' },
  { id: 'tab', label: 'Tab', data: '\t', title: 'Tab' },
  { id: 'ctrl-a', label: 'Ctrl A', data: '\x01', title: 'Ctrl+A' },
  { id: 'ctrl-c', label: 'Ctrl C', data: '\x03', title: 'Ctrl+C' },
  { id: 'ctrl-d', label: 'Ctrl D', data: '\x04', title: 'Ctrl+D' },
  { id: 'ctrl-e', label: 'Ctrl E', data: '\x05', title: 'Ctrl+E' },
  { id: 'ctrl-l', label: 'Ctrl L', data: '\x0c', title: 'Ctrl+L' },
  { id: 'ctrl-z', label: 'Ctrl Z', data: '\x1a', title: 'Ctrl+Z' },
  { id: 'up', label: '↑', data: '\x1b[A', title: 'Arrow Up' },
  { id: 'down', label: '↓', data: '\x1b[B', title: 'Arrow Down' },
  { id: 'left', label: '←', data: '\x1b[D', title: 'Arrow Left' },
  { id: 'right', label: '→', data: '\x1b[C', title: 'Arrow Right' },
  { id: 'home', label: 'Home', data: '\x1b[H', title: 'Home' },
  { id: 'end', label: 'End', data: '\x1b[F', title: 'End' },
  { id: 'page-up', label: 'PgUp', data: '\x1b[5~', title: 'Page Up' },
  { id: 'page-down', label: 'PgDn', data: '\x1b[6~', title: 'Page Down' },
  { id: 'enter', label: 'Enter', data: '\r', title: 'Enter' },
  { id: 'backspace', label: '⌫', data: '\x7f', title: 'Backspace' },
  { id: 'delete', label: 'Del', data: '\x1b[3~', title: 'Delete' },
  { id: 'pipe', label: '|', data: '|', title: 'Pipe' },
  { id: 'tilde', label: '~', data: '~', title: 'Tilde' },
  { id: 'slash', label: '/', data: '/', title: 'Slash' },
  { id: 'dash', label: '-', data: '-', title: 'Dash' },
  { id: 'underscore', label: '_', data: '_', title: 'Underscore' }
];

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
  activeTerminalFit = null;
  activeTerminalInput = null;
  activeTerminalFocus = null;
  activeTerminalBlur = null;
  document.body.classList.remove('terminal-page');
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
      try {
        const ticket = await api<{ terminalUrl: string }>('terminal/tickets', {
          method: 'POST',
          json: { accessToken: token, targetId }
        });
        location.href = ticket.terminalUrl;
      } catch (error) {
        showMessage((error as Error).message, 'error');
      }
    });
  }
}

function targetCard(target: Target) {
  return `
    <article class="target-card">
      <div>
        <h2>${escapeHtml(target.name)}</h2>
        <p>${escapeHtml(target.sshUsername)}@${escapeHtml(target.host)}:${target.port}</p>
      </div>
      <button class="button primary" type="button" data-connect-target="${target.id}">打开终端</button>
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
            <button id="terminalFitButton" class="button small ghost" type="button">适配</button>
            <button id="terminalFullscreenButton" class="button small" type="button">全屏</button>
          </div>
        </div>
        <div id="terminal"></div>
        <div id="mobileTerminalToolbar" class="mobile-terminal-toolbar" aria-label="移动端终端辅助按键">
          <div class="mobile-terminal-toolbar-row">
            ${terminalKeyButtons()}
            <button id="terminalKeyboardButton" class="terminal-key wide" type="button" title="显示或隐藏系统键盘">键盘</button>
          </div>
        </div>
      </section>
    </section>
  `));

  document.body.classList.add('terminal-page');
  setupTerminalLayoutControls();
  setupTerminalViewportControls();
  setupTerminalMobileToolbar();

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

function terminalKeyButtons() {
  return TERMINAL_KEY_ACTIONS.map((action) => `
    <button class="terminal-key${action.wide ? ' wide' : ''}" type="button" data-terminal-key="${action.id}" title="${escapeHtml(action.title)}">${escapeHtml(action.label)}</button>
  `).join('');
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
  term.writeln('Connecting...');

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
  activeTerminalFocus = () => term.focus();
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
    }
    if (message.type === 'error') {
      showMessage(message.message, 'error');
      term.writeln(`\r\n${message.message}`);
    }
    if (message.type === 'closed') term.writeln('\r\nSession closed.');
  });

  ws.addEventListener('error', () => {
    const message = socketOpened
      ? 'SSH 终端连接异常，请检查 SSH 凭据或目标主机状态。'
      : 'WebSocket 连接失败，请检查登录状态、目标权限或重新打开终端。';
    showMessage(message, 'error');
    term.writeln(`\r\n${message}`);
  });

  ws.addEventListener('close', () => {
    if (!terminalReady) {
      showMessage('终端未能建立连接，请返回目标列表重新打开终端。', 'error');
    }
    term.writeln('\r\nDisconnected.');
  });

  term.onData((data) => {
    sendTerminalData(data);
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

  for (const button of toolbar.querySelectorAll<HTMLButtonElement>('[data-terminal-key]')) {
    button.addEventListener('click', () => {
      const action = TERMINAL_KEY_ACTIONS.find((item) => item.id === button.dataset.terminalKey);
      if (!action) return;
      activeTerminalInput?.(action.data);
      activeTerminalFocus?.();
    });
  }

  document.querySelector<HTMLButtonElement>('#terminalKeyboardButton')?.addEventListener('click', () => {
    const terminalElement = document.querySelector<HTMLElement>('#terminal .xterm');
    if (terminalElement && document.activeElement && terminalElement.contains(document.activeElement)) {
      activeTerminalBlur?.();
      return;
    }
    activeTerminalFocus?.();
  });
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

  fullscreenButton?.addEventListener('click', async () => {
    try {
      if (document.fullscreenElement === terminalPanel) {
        await document.exitFullscreen();
      } else {
        await terminalPanel.requestFullscreen();
      }
      scheduleTerminalFit();
    } catch (error) {
      showMessage((error as Error).message, 'error');
    }
  });

  document.addEventListener('fullscreenchange', () => {
    if (fullscreenButton) {
      fullscreenButton.textContent = document.fullscreenElement === terminalPanel ? '退出全屏' : '全屏';
    }
    scheduleTerminalFit();
  });

  if (!handle) return;

  const setConnectWidth = (clientX: number) => {
    const rect = shell.getBoundingClientRect();
    const max = Math.max(280, rect.width - 420);
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
  const me = await api<{ authenticated: boolean; user?: User }>('me');
  if (!me.authenticated || me.user?.role !== 'admin') {
    setView(shell(`
      <section class="panel">
        <h1>需要管理员登录</h1>
        <p class="muted">请先通过管理员专属访问链接完成密码和 TOTP 双因子登录。</p>
      </section>
    `));
    return;
  }

  const [{ users, links }, { targets }] = await Promise.all([
    api<{ users: User[]; links: Array<Record<string, unknown>> }>('admin/users'),
    api<{ targets: Target[] }>('admin/targets')
  ]);

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
      showMessage(`用户已创建，访问链接：${result.accessUrl}`);
      await renderAdmin();
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

  document.querySelectorAll<HTMLButtonElement>('[data-link-user]').forEach((button) => {
    button.addEventListener('click', async () => {
      try {
        const result = await api<{ accessUrl: string }>(`admin/users/${button.dataset.linkUser}/access-links`, {
          method: 'POST',
          json: { label: 'manual' }
        });
        showMessage(`新访问链接：${result.accessUrl}`);
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
}

async function loadPermissions(userId: number) {
  const payload = await api<{ targetIds: number[] }>(`admin/users/${userId}/permissions`);
  const allowed = new Set(payload.targetIds);
  document.querySelectorAll<HTMLInputElement>('#permissionForm input[name="targetIds"]').forEach((input) => {
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
