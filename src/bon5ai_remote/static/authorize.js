// Agent sign-in: show the pending request's ID, wait for the person to approve it at the
// terminal, then send the browser back to the agent with the result. The page holds no
// secret of its own: an HttpOnly cookie identifies the request to authorize-status.

const $ = id => document.getElementById(id);
const POLL_MS = 1000;
// Which sign-in this tab is waiting on; its own cookie is named after it.
const REQUEST = new URLSearchParams(location.search).get('request') ?? '';

function say(text, tone = 'rm-muted') {
  $('message').className = tone;
  $('message').textContent = text;
}

function minutes(seconds) {
  const m = Math.floor(seconds / 60);
  const s = String(seconds % 60).padStart(2, '0');
  return `${m}:${s}`;
}

// Click the command or the ID to copy it. The clipboard API needs a secure context
// (https, or http on loopback); elsewhere, fall back to a selected textarea and the
// older copy command, which a click still allows.
let requestId = '';

function copyFallback(text) {
  const area = document.createElement('textarea');
  area.value = text;
  area.className = 'rm-offscreen';
  document.body.append(area);
  area.select();
  const copied = document.execCommand('copy');
  area.remove();
  return copied;
}

async function copy(button, text) {
  let copied;
  try {
    await navigator.clipboard.writeText(text);
    copied = true;
  } catch {
    copied = copyFallback(text);
    button.focus();
  }
  const hint = button.querySelector('.rm-copy-hint');
  hint.textContent = copied ? 'Copied' : "Couldn't copy";
  clearTimeout(button.resetHint);
  button.resetHint = setTimeout(() => { hint.textContent = 'Copy'; }, 2000);
}

$('copy-command').addEventListener('click', event =>
  copy(event.currentTarget, `tmux-remote-viewer agent approve ${requestId}`));
$('copy-id').addEventListener('click', event => copy(event.currentTarget, requestId));

function show(request) {
  $('waiting').hidden = false;
  requestId = request.id;
  $('request-id').textContent = request.id;
  $('command-id').textContent = request.id;
  // The name is the agent's own words; the identity line is the gate's, kept apart so a
  // name can't dress itself up as verified.
  $('client').textContent = request.client;
  $('identity').textContent = request.verified
    ? `verified: ${request.clientHost}`
    : 'not verified: the agent chose this name';
  $('redirect').textContent = request.redirectHost;
  $('expires').textContent = minutes(request.expiresIn);
}

async function poll() {
  let response;
  try {
    const url = new URL('authorize-status', location.href);
    url.search = new URLSearchParams({ request: REQUEST }).toString();
    response = await fetch(url, { cache: 'no-store' });
  } catch {
    say('Reconnecting…');
    return setTimeout(poll, POLL_MS * 3);
  }
  if (response.status === 404) {
    $('waiting').hidden = true;
    $('title').textContent = 'Sign-in not found';
    return say('This sign-in has finished or expired. Start it again from your agent.');
  }
  const request = await response.json();
  show(request);
  if (request.state === 'pending') return setTimeout(poll, POLL_MS);

  $('waiting').hidden = true;
  const outcome = {
    approved: ['Approved', 'Returning to your agent…', 'rm-ok'],
    denied: ['Denied', 'The request was denied at the terminal.', 'rm-warn'],
    expired: ['Expired', 'Nobody approved the request in time. Start the sign-in again.', 'rm-warn'],
  }[request.state] ?? ['Finished', '', 'rm-muted'];
  $('title').textContent = outcome[0];
  say(outcome[1], outcome[2]);
  // The redirect is handed out once. It always goes to the address the agent registered:
  // a localhost port on the agent's machine, or one the server explicitly allows.
  if (request.redirect) location.assign(request.redirect);
}

poll();
