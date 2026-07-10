'use strict';

var currentUser = null;
var requires2fa = false;

(function initMatrixRain() {
  var canvas = document.getElementById('matrix-bg');
  if (!canvas) return;
  var ctx = canvas.getContext('2d');
  if (!ctx) return;
  var matrixColor = getComputedStyle(document.documentElement).getPropertyValue('--green-bright').trim();
  function resize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
  }
  resize();
  window.addEventListener('resize', resize);
  var fontSize = 14;
  var columns = Math.max(1, Math.floor(canvas.width / fontSize));
  var drops = new Array(columns).fill(1);
  var chars = 'アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン0123456789ABCDEF';
  function draw() {
    ctx.fillStyle = 'rgba(2, 10, 6, 0.05)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = matrixColor;
    ctx.font = fontSize + 'px monospace';
    for (var i = 0; i < drops.length; i++) {
      var char = chars[Math.floor(Math.random() * chars.length)];
      ctx.fillText(char, i * fontSize, drops[i] * fontSize);
      if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
        drops[i] = 0;
      }
      drops[i]++;
    }
  }
  setInterval(draw, 50);
})();

function showError(msg) {
  var el = document.getElementById('error-msg');
  el.textContent = msg;
  el.hidden = false;
}

function hideError() {
  document.getElementById('error-msg').hidden = true;
}

function getCsrfToken() {
  var match = document.cookie.match(/trueid_csrf_token=([^;]+)/);
  return match ? match[1] : '';
}

async function initOidcStatus() {
  try {
    var resp = await fetch('/api/auth/oidc/status', { credentials: 'include' });
    if (!resp.ok) return;
    var data = await resp.json();
    if (!data || !data.enabled) return;
    document.getElementById('oidc-provider-name').textContent = data.provider_name || 'OIDC';
    document.getElementById('oidc-section').hidden = false;
    if (data.allow_local_login === false) {
      document.getElementById('login-form').hidden = true;
      document.getElementById('oidc-local-divider').hidden = true;
    }
  } catch (e) {}
}

document.getElementById('login-form').addEventListener('submit', async function(e) {
  e.preventDefault();
  hideError();

  var btn = document.getElementById('login-btn');
  btn.disabled = true;
  btn.textContent = 'Logging in...';

  try {
    var resp = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({
        username: document.getElementById('username').value,
        password: document.getElementById('password').value,
        totp_code: requires2fa ? document.getElementById('totp-code').value : null
      })
    });

    if (resp.status === 401) {
      var authErr = await resp.json().catch(function() { return {}; });
      if (authErr.requires_2fa) {
        requires2fa = true;
        document.getElementById('totp-wrap').hidden = false;
        showError('Two-factor code required. Enter code and submit again.');
        return;
      }
      showError('Invalid username or password.');
      return;
    }
    if (resp.status === 423) {
      var data = await resp.json();
      var msg = 'Account locked.';
      if (data.locked_until) {
        var until = new Date(data.locked_until);
        var mins = Math.ceil((until - Date.now()) / 60000);
        if (mins > 0) msg += ' Try again in ' + mins + ' minute(s).';
      }
      showError(msg);
      return;
    }
    if (!resp.ok) {
      var errData = await resp.json().catch(function() { return {}; });
      showError(errData.error || 'Login failed (HTTP ' + resp.status + ')');
      return;
    }

    var user = await resp.json();
    requires2fa = false;
    currentUser = user;

    if (user.force_password_change) {
      document.getElementById('login-form').hidden = true;
      document.getElementById('change-pw').hidden = false;
      return;
    }

    window.location = '/';
  } catch (err) {
    showError('Network error: ' + err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Log in';
  }
});

async function changePassword() {
  hideError();
  var newPw = document.getElementById('new-password').value;
  var confirmPw = document.getElementById('confirm-password').value;

  if (newPw.length < 12) {
    showError('Password must be at least 12 characters.');
    return;
  }
  if (newPw !== confirmPw) {
    showError('Passwords do not match.');
    return;
  }

  var btn = document.getElementById('change-pw-btn');
  btn.disabled = true;

  try {
    var resp = await fetch('/api/auth/change-password', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': getCsrfToken()
      },
      credentials: 'include',
      body: JSON.stringify({
        current_password: document.getElementById('password').value,
        new_password: newPw
      })
    });

    if (!resp.ok) {
      var errData = await resp.json().catch(function() { return {}; });
      showError(errData.error || 'Password change failed.');
      return;
    }

    window.location = '/';
  } catch (err) {
    showError('Network error: ' + err.message);
  } finally {
    btn.disabled = false;
  }
}

document.getElementById('change-pw-btn').addEventListener('click', changePassword);
initOidcStatus();
