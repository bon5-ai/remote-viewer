// BON5AI Remote Viewer: trade a pairing code for a viewer cookie, then watch the shared
// terminal read-only. Every URL is relative to the mount, because the gate may be served
// under a path in public (e.g. /remote/; Funnel strips the prefix) and at / when hit directly.

const base = new URL('.', location.href);
const $ = id => document.getElementById(id);
const POLL_MS = 5000;

// Shown over the empty view when there is nothing live to watch. A detached host
// ("host-away") needs no notice: its session is still running and streaming.
const NOTICES = {
  'stream-down': "Stream offline. It comes back when `tmux-remote-viewer share` runs again.",
  unreachable: 'Reconnecting…',
  'player-failed': "The player didn't load. Reload the page to try again.",
};

let player = null;
let playerLoaded = null;
let pollTimer = null;

function show(id) {
  for (const section of ['pair', 'view', 'ended']) $(section).hidden = section !== id;
}

function notice(key) {
  $('notice').textContent = NOTICES[key] ?? '';
  $('notice').hidden = !key;
}

async function api(path, options = {}) {
  const response = await fetch(new URL(path, base), { cache: 'no-store', ...options });
  const body = await response.json().catch(() => ({}));
  return { status: response.status, body };
}

function load(tag, attrs) {
  return new Promise((resolve, reject) => {
    const el = Object.assign(document.createElement(tag), attrs);
    el.onload = resolve;
    el.onerror = () => { el.remove(); reject(new Error(`${attrs.href ?? attrs.src} failed to load`)); };
    document.head.append(el);
  });
}

// Cascadia Mono is the terminal face (remote.css). Symbols Nerd Font is the one
// asciinema's own page loads for private-use icons; the gate rewrites that
// font-face onto player-fonts.css. The player measures its cell once, at create,
// so both have to be loaded first or it locks in the fallback face.
const TERM_FONT = '"Cascadia Mono", "Symbols Nerd Font", monospace';

function loadPlayer() {
  // The player comes from asciinema's own server (via the gate), so it always
  // matches the stream protocol. Loaded only once paired. The CSS must be applied
  // before the player starts: it resolves the theme's CSS variables into inline
  // colors once, and reads them as black if the stylesheet isn't there yet.
  // The symbol font sheet is best-effort: an older stream simply has none.
  playerLoaded ??= Promise.all([
    load('link', { rel: 'stylesheet', href: new URL('player.css', base) }),
    load('link', { rel: 'stylesheet', href: new URL('player-fonts.css', base) }).catch(() => {}),
    load('script', { src: new URL('player.js', base) }),
  ]).then(() => Promise.all([
    document.fonts.load('400 16px "Cascadia Mono"'),
    document.fonts.load('700 16px "Cascadia Mono"'),
    document.fonts.load('italic 400 16px "Cascadia Mono"'),
    document.fonts.load('italic 700 16px "Cascadia Mono"'),
    document.fonts.load('16px "Symbols Nerd Font"'),
  ].map(font => font.catch(() => []))))
    .catch(error => { playerLoaded = null; throw error; });
  return playerLoaded;
}

async function startPlayer() {
  await loadPlayer();
  if (player) return;
  const url = new URL('ws', base);
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
  const created = AsciinemaPlayer.create({ driver: 'websocket', url: url.href }, $('player'), {
    fit: 'both', autoPlay: true, controls: false, terminalFontFamily: TERM_FONT,
  });
  // The player gives up for good when its socket closes cleanly, which is what a stream
  // restart looks like, and a restart can be quicker than one status poll. So whenever
  // it stops, drop it and check status soon; refresh() starts a new one once the stream
  // is back.
  const stopped = () => {
    clearTimeout(pollTimer);
    pollTimer = setTimeout(() => {
      if (player === created) stopPlayer();
      refresh();
    }, 1000);
  };
  for (const name of ['ended', 'offline', 'errored']) created.addEventListener(name, stopped);
  // Paint the margin around the terminal in the terminal's own background, so the
  // letterboxing left by fitting a fixed grid to the viewport doesn't show as a box.
  created.addEventListener('metadata', () => {
    const el = created.el?.querySelector('.ap-player');
    const background = el && getComputedStyle(el).getPropertyValue('--term-color-background').trim();
    if (background) $('view').style.setProperty('--rm-term-bg', background);
  });
  player = created;
}

function stopPlayer() {
  player?.dispose();
  player = null;
  $('player').replaceChildren();
}

async function refresh() {
  let result;
  try {
    result = await api('status');
  } catch {
    if (!player) notice('unreachable');
    return schedule();
  }
  const { status, body } = result;
  if (status === 401) {
    stopPlayer();
    return show('pair');
  }
  if (body.state === 'ended') {
    stopPlayer();
    return show('ended'); // the gate has already dropped this viewer
  }
  show('view');
  if (body.state === 'stream-down') {
    stopPlayer();
    notice('stream-down');
  } else {
    notice(null);
    if (!player) await startPlayer().catch(() => notice('player-failed'));
  }
  schedule();
}

function schedule() {
  clearTimeout(pollTimer);
  pollTimer = setTimeout(refresh, POLL_MS);
}

async function claim(code) {
  const { status, body } = await api('claim', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code }),
  }).catch(() => ({ status: 0, body: {} }));
  return status === 200 ? null : (body.error ?? "Couldn't reach the server. Try again.");
}

// The QR code `tmux-remote-viewer share` prints opens <public url>#code=XXXX-XXXX. A fragment never leaves
// the browser, so the code is in no CDN, Funnel or gate log. Claim it, and take it out
// of the address bar so a reload or a shared link doesn't carry a used code.
async function claimFromLink() {
  const code = new URLSearchParams(location.hash.slice(1)).get('code');
  if (!code) return;
  history.replaceState(null, '', location.pathname + location.search);
  $('pair-error').textContent = (await claim(code)) ?? '';
}

// Codes are 8 letters and digits, shown as XXXX-XXXX. Format them as they are typed or
// pasted: uppercase, nothing else, at most 8, and the dash once a fifth character
// arrives (adding it after the fourth would fight Backspace).
const CODE_LENGTH = 8;

function formatCode(text) {
  const chars = text.toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, CODE_LENGTH);
  return chars.length > 4 ? `${chars.slice(0, 4)}-${chars.slice(4)}` : chars;
}

function reformatCode(event) {
  if (event.isComposing) return;  // a mobile keyboard's word in progress; compositionend follows
  const input = $('code');
  $('pair-error').textContent = '';
  // Keep the caret after the same character it followed.
  const caret = formatCode(input.value.slice(0, input.selectionStart)).length;
  input.value = formatCode(input.value);
  input.setSelectionRange(caret, caret);
}

$('code').addEventListener('input', reformatCode);
$('code').addEventListener('compositionend', reformatCode);

$('pair-form').addEventListener('submit', async event => {
  event.preventDefault();
  $('pair-error').textContent = '';
  if (formatCode($('code').value).length < CODE_LENGTH + 1) {  // + 1 for the dash
    $('pair-error').textContent = `Enter all ${CODE_LENGTH} characters.`;
    return;
  }
  const error = await claim($('code').value);
  if (error) {
    $('pair-error').textContent = error;
    return;
  }
  $('code').value = '';
  refresh();
});

$('again').addEventListener('click', () => show('pair'));

// ---- full screen ----------------------------------------------------------------
// The whole page goes full screen, not the player, so this button stays on top.
// Safari on iPhone has no element full screen; the button stays hidden there.
const root = document.documentElement;
const fullscreenElement = () => document.fullscreenElement ?? document.webkitFullscreenElement ?? null;

function syncFullscreen() {
  const on = fullscreenElement() !== null;
  $('fullscreen').setAttribute('aria-pressed', String(on));
  $('fullscreen').setAttribute('aria-label', on ? 'Exit full screen' : 'Enter full screen');
  $('fullscreen').title = on ? 'Exit full screen' : 'Full screen';
}

if (document.fullscreenEnabled || document.webkitFullscreenEnabled) {
  $('fullscreen').hidden = false;
  $('fullscreen').addEventListener('click', () => {
    const request = fullscreenElement()
      ? (document.exitFullscreen ?? document.webkitExitFullscreen).call(document)
      : (root.requestFullscreen ?? root.webkitRequestFullscreen).call(root);
    Promise.resolve(request).catch(() => {});
  });
  document.addEventListener('fullscreenchange', syncFullscreen);
  document.addEventListener('webkitfullscreenchange', syncFullscreen);
  syncFullscreen();
}

window.addEventListener('hashchange', () => claimFromLink().then(refresh));
claimFromLink().then(refresh);
