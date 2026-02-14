/* Admin module (status, retention, security, audit). */

async function openSecurityModal() {
        document.getElementById('security-modal').style.display = '';
        document.getElementById('totp-setup-box').style.display = 'none';
        document.getElementById('totp-backup-codes').style.display = 'none';
        await loadTotpStatus();
      }

      function closeSecurityModal() {
        document.getElementById('security-modal').style.display = 'none';
      }

      async function loadTotpStatus() {
        var box = document.getElementById('totp-status-box');
        try {
          var resp = await fetch('/api/auth/totp/status', { credentials: 'include' });
          if (!resp.ok) throw new Error('HTTP ' + resp.status);
          var data = await resp.json();
          var enabled = !!data.enabled;
          box.innerHTML =
            '<div>2FA status: <strong style="color:' + (enabled ? 'var(--status-ok)' : 'var(--status-warn)') + ';">' + (enabled ? 'Enabled' : 'Disabled') + '</strong></div>' +
            '<div class="muted" style="margin-top:6px;">Verified at: ' + escapeHtml(data.verified_at || '-') + '</div>' +
            '<div style="display:flex;gap:8px;margin-top:10px;">' +
              (enabled
                ? '<button class="btn btn-sm" onclick="disableTotp()">Disable 2FA</button><button class="btn btn-sm" onclick="regenBackupCodes()">Regenerate Backup Codes</button>'
                : '<button class="btn btn-sm" onclick="startTotpSetup()">Enable 2FA</button>') +
            '</div>';
        } catch (e) {
          box.innerHTML = '<span style="color:var(--status-error);">Failed: ' + escapeHtml(e.message) + '</span>';
        }
      }

      async function startTotpSetup() {
        try {
          var resp = await fetch('/api/auth/totp/setup', {
            method: 'POST',
            headers: mutHeaders(),
            credentials: 'include',
            body: JSON.stringify({})
          });
          if (!resp.ok) throw new Error('HTTP ' + resp.status);
          var data = await resp.json();
          document.getElementById('totp-setup-box').style.display = '';
          document.getElementById('totp-qr').src = data.qr_code || '';
          document.getElementById('totp-secret-line').textContent = 'Secret: ' + (data.secret || '-');
        } catch (e) {
          alert('TOTP setup failed: ' + e.message);
        }
      }

      async function verifyTotpSetup() {
        var code = (document.getElementById('totp-verify-code').value || '').trim();
        if (!code) return;
        try {
          var resp = await fetch('/api/auth/totp/verify', {
            method: 'POST',
            headers: mutHeaders(),
            credentials: 'include',
            body: JSON.stringify({ code: code })
          });
          if (!resp.ok) {
            var txt = await resp.text();
            throw new Error('HTTP ' + resp.status + ' ' + txt);
          }
          var data = await resp.json();
          var codes = (data.backup_codes || []).join('\n');
          document.getElementById('totp-backup-codes').style.display = '';
          document.getElementById('totp-backup-codes').textContent = 'Backup codes (save now):\n' + codes;
          document.getElementById('totp-setup-box').style.display = 'none';
          await loadTotpStatus();
        } catch (e) {
          alert('TOTP verify failed: ' + e.message);
        }
      }

      async function disableTotp() {
        var code = prompt('Enter current TOTP or backup code to disable 2FA:');
        if (!code) return;
        try {
          var resp = await fetch('/api/auth/totp/disable', {
            method: 'POST',
            headers: mutHeaders(),
            credentials: 'include',
            body: JSON.stringify({ code: code })
          });
          if (!resp.ok) throw new Error('HTTP ' + resp.status);
          document.getElementById('totp-backup-codes').style.display = 'none';
          await loadTotpStatus();
        } catch (e) {
          alert('Disable failed: ' + e.message);
        }
      }

      async function regenBackupCodes() {
        try {
          var resp = await fetch('/api/auth/totp/backup-codes', {
            method: 'POST',
            headers: mutHeaders(),
            credentials: 'include',
            body: JSON.stringify({})
          });
          if (!resp.ok) throw new Error('HTTP ' + resp.status);
          var data = await resp.json();
          document.getElementById('totp-backup-codes').style.display = '';
          document.getElementById('totp-backup-codes').textContent =
            'New backup codes (save now):\n' + (data.backup_codes || []).join('\n');
        } catch (e) {
          alert('Regenerate failed: ' + e.message);
        }
      }

      async function loadAdminSecuritySection() {
        if (!currentUser || currentUser.role !== 'Admin') return;
        try {
          var policyRes = await fetch('/api/v2/admin/security/password-policy', { credentials: 'include' });
          if (!policyRes.ok) throw new Error('HTTP ' + policyRes.status);
          var p = await policyRes.json();
          document.getElementById('admin-security-policy').innerHTML =
            '<div class="setting-row"><span class="setting-title">Min Length</span><input id="sec-min-length" class="setting-input" style="width:120px;" type="number" min="8" value="' + escapeHtml(p.min_length) + '"></div>' +
            '<div class="setting-row"><span class="setting-title">Require Special</span><input id="sec-require-special" type="checkbox" ' + (p.require_special ? 'checked' : '') + '></div>' +
            '<div class="setting-row"><span class="setting-title">History Count</span><input id="sec-history-count" class="setting-input" style="width:120px;" type="number" min="0" value="' + escapeHtml(p.history_count) + '"></div>' +
            '<div class="setting-row"><span class="setting-title">Session Idle Minutes</span><input id="sec-idle-minutes" class="setting-input" style="width:120px;" type="number" min="1" value="' + escapeHtml(p.session_max_idle_minutes) + '"></div>' +
            '<div class="setting-row"><span class="setting-title">Session Max Hours</span><input id="sec-max-hours" class="setting-input" style="width:120px;" type="number" min="1" value="' + escapeHtml(p.session_absolute_max_hours) + '"></div>' +
            '<div class="setting-row"><span class="setting-title">TOTP Required for Admins</span><input id="sec-totp-required" type="checkbox" ' + (p.totp_required_for_admins ? 'checked' : '') + '></div>';
        } catch (e) {
          document.getElementById('admin-security-policy').innerHTML = '<span style="color:var(--status-error);">Failed: ' + escapeHtml(e.message) + '</span>';
        }
        try {
          var sRes = await fetch('/api/v2/admin/security/sessions', { credentials: 'include' });
          if (!sRes.ok) throw new Error('HTTP ' + sRes.status);
          var sessions = await sRes.json();
          if (!Array.isArray(sessions) || !sessions.length) {
            document.getElementById('admin-security-sessions').innerHTML = '<span class="muted">No active sessions.</span>';
            return;
          }
          document.getElementById('admin-security-sessions').innerHTML = sessions.map(function (s) {
            return '<div style="padding:6px 0;border-bottom:1px solid var(--border-dim);">' +
              '<strong>' + escapeHtml(s.username) + '</strong> @ ' + escapeHtml(s.ip_address || '-') +
              ' <span class="muted">' + escapeHtml(timeAgo(s.last_active_at)) + '</span> ' +
              '<button class="btn btn-sm role-admin" onclick="terminateAdminSession(' + s.id + ')">Terminate</button>' +
              '</div>';
          }).join('');
        } catch (e2) {
          document.getElementById('admin-security-sessions').innerHTML = '<span style="color:var(--status-error);">Failed: ' + escapeHtml(e2.message) + '</span>';
        }
      }

      async function saveAdminSecurityPolicy() {
        if (!currentUser || currentUser.role !== 'Admin') return;
        var body = {
          min_length: parseInt(document.getElementById('sec-min-length').value || '12', 10),
          require_uppercase: true,
          require_lowercase: true,
          require_digit: true,
          require_special: !!document.getElementById('sec-require-special').checked,
          history_count: parseInt(document.getElementById('sec-history-count').value || '5', 10),
          max_age_days: 0,
          session_max_idle_minutes: parseInt(document.getElementById('sec-idle-minutes').value || '480', 10),
          session_absolute_max_hours: parseInt(document.getElementById('sec-max-hours').value || '24', 10),
          totp_required_for_admins: !!document.getElementById('sec-totp-required').checked
        };
        try {
          var resp = await fetch('/api/v2/admin/security/password-policy', {
            method: 'PUT',
            headers: mutHeaders(),
            credentials: 'include',
            body: JSON.stringify(body)
          });
          if (!resp.ok) throw new Error('HTTP ' + resp.status);
          document.getElementById('admin-security-result').textContent = 'Saved';
          document.getElementById('admin-security-result').style.color = 'var(--status-ok)';
          await loadAdminSecuritySection();
        } catch (e) {
          document.getElementById('admin-security-result').textContent = 'Failed: ' + e.message;
          document.getElementById('admin-security-result').style.color = 'var(--status-error)';
        }
      }

      async function terminateAdminSession(id) {
        try {
          var resp = await fetch('/api/v2/admin/security/sessions/' + encodeURIComponent(id), {
            method: 'DELETE',
            headers: mutHeaders(),
            credentials: 'include'
          });
          if (!resp.ok) throw new Error('HTTP ' + resp.status);
          await loadAdminSecuritySection();
        } catch (e) {
          alert('Terminate failed: ' + e.message);
        }
      }

      async function quickAddTag() {
        var ip = document.getElementById('status-tag-ip').value.trim();
        var tag = document.getElementById('status-tag-name').value.trim();
        var color = document.getElementById('status-tag-color').value.trim();
        if (!ip || !tag) return;
        try {
          var res = await fetch('/api/v2/tags', {
            method: 'POST',
            headers: mutHeaders(),
            credentials: 'include',
            body: JSON.stringify({ ip: ip, tag: tag, color: color || 'var(--text-secondary)' })
          });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          document.getElementById('status-tag-ip').value = '';
          document.getElementById('status-tag-name').value = '';
          await loadStatusTags();
        } catch (e) {
          alert('Add tag failed: ' + e.message);
        }
      }

      async function loadStatusTags() {
        if (!currentUser || currentUser.role !== 'Admin') return;
        var el = document.getElementById('status-tags-list');
        try {
          var res = await fetch('/api/v2/tags', { credentials: 'include' });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          var body = await res.json();
          var rows = body.data || [];
          if (!rows.length) {
            el.innerHTML = '<span class="muted">No tags defined.</span>';
            return;
          }
          el.innerHTML = rows.map(function (r) {
            return '<div style="padding:4px 0;border-bottom:1px solid var(--border-dim);">' +
              '<span class="badge" style="border:1px solid ' + escapeHtml(r.color || 'var(--text-secondary)') + ';color:' + escapeHtml(r.color || 'var(--text-secondary)') + ';">' + escapeHtml(r.tag) + '</span> ' +
              '<span class="muted">' + escapeHtml(r.ip_count || 0) + ' IPs</span>' +
              '</div>';
          }).join('');
        } catch (e) {
          el.innerHTML = '<span style="color:var(--status-error);">Failed: ' + escapeHtml(e.message) + '</span>';
        }
      }

      async function loadRetentionSection() {
        await loadRetentionPolicies();
        await loadRetentionStats();
      }

      async function loadRetentionPolicies() {
        try {
          var res = await fetch('/api/v2/admin/retention', { credentials: 'include' });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          var data = await res.json();
          var rows = data.policies || [];
          if (!rows.length) {
            document.getElementById('retention-body').innerHTML =
              '<tr><td colspan="6" class="muted">No retention policies configured.</td></tr>';
            return;
          }
          document.getElementById('retention-body').innerHTML = rows.map(function (r) {
            return '<tr>' +
              '<td>' + escapeHtml(r.table_name) + '</td>' +
              '<td><input id="ret-days-' + escJs(r.table_name) + '" class="setting-input" style="width:110px;" type="number" min="1" value="' + escapeHtml(r.retention_days) + '"> days</td>' +
              '<td><input id="ret-enabled-' + escJs(r.table_name) + '" type="checkbox" ' + (r.enabled ? 'checked' : '') + '></td>' +
              '<td>' + escapeHtml(timeAgo(r.last_run_at)) + '</td>' +
              '<td>' + escapeHtml(r.last_deleted_count || 0) + '</td>' +
              '<td><button class="btn btn-sm role-admin" onclick="saveRetentionPolicy(\'' + escJs(r.table_name) + '\')">Save</button></td>' +
              '</tr>';
          }).join('');
        } catch (e) {
          document.getElementById('retention-body').innerHTML =
            '<tr><td colspan="6" style="color:var(--status-error);">Failed: ' + escapeHtml(e.message) + '</td></tr>';
        }
      }

      async function saveRetentionPolicy(tableName) {
        var daysInput = document.getElementById('ret-days-' + tableName);
        var enabledInput = document.getElementById('ret-enabled-' + tableName);
        if (!daysInput || !enabledInput) return;
        var payload = {
          retention_days: parseInt(daysInput.value || '90', 10),
          enabled: !!enabledInput.checked
        };
        try {
          var res = await fetch('/api/v2/admin/retention/' + encodeURIComponent(tableName), {
            method: 'PUT',
            headers: mutHeaders(),
            credentials: 'include',
            body: JSON.stringify(payload)
          });
          if (!res.ok) {
            var txt = await res.text();
            throw new Error('HTTP ' + res.status + ' ' + txt);
          }
          await loadRetentionSection();
        } catch (e) {
          alert('Retention update failed: ' + e.message);
        }
      }

      async function runRetentionNow() {
        var result = document.getElementById('retention-run-result');
        result.textContent = 'Running...';
        try {
          var res = await fetch('/api/v2/admin/retention/run', {
            method: 'POST',
            headers: mutHeaders(),
            credentials: 'include',
            body: JSON.stringify({})
          });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          var body = await res.json();
          var rows = body.results || [];
          var changed = rows.filter(function (r) { return (r.deleted || 0) > 0; }).length;
          result.textContent = 'Done. Policies with deletions: ' + changed;
          result.style.color = 'var(--status-ok)';
          await loadRetentionSection();
        } catch (e) {
          result.textContent = 'Failed: ' + e.message;
          result.style.color = 'var(--status-error)';
        }
      }

      async function loadRetentionStats() {
        try {
          var res = await fetch('/api/v2/admin/retention/stats', { credentials: 'include' });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          var data = await res.json();
          var dbSize = data.database_size_bytes || 0;
          var rows = data.tables || [];
          var top = '<div><strong>Database size:</strong> ' + escapeHtml(Math.round(dbSize / 1024 / 1024 * 100) / 100 + ' MB') + '</div>';
          var list = rows.map(function (r) {
            return '<div class="setting-row" style="padding:4px 0;">' +
              '<div class="setting-label"><span class="setting-title">' + escapeHtml(r.table_name) + '</span></div>' +
              '<div>' + escapeHtml(r.row_count) + ' rows, oldest: ' + escapeHtml(r.oldest_row || '-') + '</div>' +
              '</div>';
          }).join('');
          document.getElementById('retention-stats').innerHTML = top + list;
        } catch (e) {
          document.getElementById('retention-stats').innerHTML =
            '<span style="color:var(--status-error);">Failed: ' + escapeHtml(e.message) + '</span>';
        }
      }

      async function loadSystemStatus() {
        try {
          var adaptersRes = await fetch('/api/v1/admin/adapters', { credentials: 'include' });
          if (!adaptersRes.ok) throw new Error('HTTP ' + adaptersRes.status);
          var adapters = await adaptersRes.json();
          var body = document.getElementById('status-adapters-body');
          if (!Array.isArray(adapters) || !adapters.length) {
            body.innerHTML = '<tr><td colspan="5" class="muted">No adapter data.</td></tr>';
          } else {
            body.innerHTML = adapters.map(function (a) {
              var status = a.status || 'unknown';
              var dot = '<span class="dot offline"></span>';
              if (status === 'listening') dot = '<span class="dot online"></span>';
              if (status === 'starting') dot = '<span class="dot" style="background:var(--status-warn);box-shadow:0 0 6px var(--status-warn);"></span>';
              return '<tr>' +
                '<td>' + escapeHtml(a.name || '-') + '</td>' +
                '<td>' + escapeHtml(a.bind || '-') + '</td>' +
                '<td>' + dot + escapeHtml(status) + '</td>' +
                '<td>' + escapeHtml(a.events_total != null ? a.events_total : 0) + '</td>' +
                '<td>' + escapeHtml(timeAgo(a.last_event_at)) + '</td>' +
                '</tr>';
            }).join('');
          }
        } catch (e) {
          document.getElementById('status-adapters-body').innerHTML =
            '<tr><td colspan="5" style="color:var(--status-error);">Failed: ' + escapeHtml(e.message) + '</td></tr>';
        }

        try {
          var cfgRes = await fetch('/api/v1/admin/runtime-config', { credentials: 'include' });
          if (!cfgRes.ok) throw new Error('HTTP ' + cfgRes.status);
          var cfg = await cfgRes.json();
          var rows = [
            ['database_url', maskedDbUrl(cfg.database_url)],
            ['radius_bind', cfg.radius_bind || '-'],
            ['radius_secret_set', yesNoBadge(!!cfg.radius_secret_set)],
            ['ad_syslog_bind', cfg.ad_syslog_bind || '-'],
            ['dhcp_syslog_bind', cfg.dhcp_syslog_bind || '-'],
            ['ad_tls_bind', cfg.ad_tls_bind || '-'],
            ['dhcp_tls_bind', cfg.dhcp_tls_bind || '-'],
            ['tls_enabled', yesNoBadge(!!cfg.tls_enabled)],
            ['oui_csv_path', cfg.oui_csv_path || '-'],
            ['admin_http_bind', cfg.admin_http_bind || '-']
          ];
          document.getElementById('status-runtime').innerHTML = rows.map(function (r) {
            return '<div class="setting-row" style="padding:6px 0;"><div class="setting-label"><span class="setting-title">' +
              escapeHtml(r[0]) + '</span></div><div>' + r[1] + '</div></div>';
          }).join('');
        } catch (e2) {
          document.getElementById('status-runtime').innerHTML =
            '<span style="color:var(--status-error);">Failed: ' + escapeHtml(e2.message) + '</span>';
        }

        await loadRetentionSection();
        await loadAdminSecuritySection();
        await loadStatusTags();
      }

      async function loadAuditLogs(page) {
        auditCurrentPage = page || 1;
        var action = document.getElementById('audit-filter-action').value.trim();
        var user = document.getElementById('audit-filter-user').value.trim();
        var params = new URLSearchParams({ page: auditCurrentPage, per_page: 50 });
        if (action) params.set('action', action);
        if (user) params.set('username', user);

        try {
          var res = await fetch('/api/v1/audit-logs?' + params.toString(), { credentials: 'include' });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          var data = await res.json();
          renderAuditTable(data.entries);
          renderAuditPaging(data.page, data.per_page, data.total);
        } catch (err) {
          document.getElementById('audit-body').innerHTML =
            '<tr><td colspan="7" style="color:var(--status-error);">Failed: ' + err.message + '</td></tr>';
        }
      }

      async function loadAuditStats() {
        try {
          var res = await fetch('/api/v1/audit-logs/stats', { credentials: 'include' });
          if (!res.ok) return;
          var s = await res.json();
          document.getElementById('audit-stats').innerHTML =
            '<span>Total: <strong>' + s.total + '</strong></span>' +
            '<span>Last 24h: <strong>' + s.last_24h + '</strong></span>' +
            '<span>Last 7d: <strong>' + s.last_7d + '</strong></span>';
        } catch (e) {}
      }

      function renderAuditTable(entries) {
        var body = document.getElementById('audit-body');
        if (!entries || entries.length === 0) {
          body.innerHTML = '<tr><td colspan="7" class="muted">No audit entries.</td></tr>';
          return;
        }
        body.innerHTML = entries.map(function(e) {
          var ts = e.timestamp ? new Date(e.timestamp).toLocaleString() : '-';
          return '<tr>' +
            '<td>' + ts + '</td>' +
            '<td>' + (e.username || '-') + '</td>' +
            '<td>' + (e.principal_type || '-') + '</td>' +
            '<td>' + (e.action || '-') + '</td>' +
            '<td>' + (e.target || '-') + '</td>' +
            '<td>' + (e.ip_address || '-') + '</td>' +
            '<td style="font-size:11px;color:var(--text-secondary);">' + (e.request_id || '-') + '</td>' +
            '</tr>';
        }).join('');
      }

      function renderAuditPaging(page, perPage, total) {
        var totalPages = Math.ceil(total / perPage) || 1;
        var el = document.getElementById('audit-paging');
        var html = 'Page ' + page + ' of ' + totalPages + ' (' + total + ' entries) &nbsp;';
        if (page > 1) html += '<button class="btn btn-sm" onclick="loadAuditLogs(' + (page - 1) + ')">← Prev</button> ';
        if (page < totalPages) html += '<button class="btn btn-sm" onclick="loadAuditLogs(' + (page + 1) + ')">Next →</button>';
        el.innerHTML = html;
      }

(function () {
  window.TrueID = window.TrueID || {};
  if (typeof window.closeSecurityModal === 'function') window.TrueID.closeSecurityModal = window.closeSecurityModal;
  if (typeof window.disableTotp === 'function') window.TrueID.disableTotp = window.disableTotp;
  if (typeof window.loadAdminSecuritySection === 'function') window.TrueID.loadAdminSecuritySection = window.loadAdminSecuritySection;
  if (typeof window.loadAuditLogs === 'function') window.TrueID.loadAuditLogs = window.loadAuditLogs;
  if (typeof window.loadAuditStats === 'function') window.TrueID.loadAuditStats = window.loadAuditStats;
  if (typeof window.loadRetentionPolicies === 'function') window.TrueID.loadRetentionPolicies = window.loadRetentionPolicies;
  if (typeof window.loadRetentionSection === 'function') window.TrueID.loadRetentionSection = window.loadRetentionSection;
  if (typeof window.loadRetentionStats === 'function') window.TrueID.loadRetentionStats = window.loadRetentionStats;
  if (typeof window.loadStatusTags === 'function') window.TrueID.loadStatusTags = window.loadStatusTags;
  if (typeof window.loadSystemStatus === 'function') window.TrueID.loadSystemStatus = window.loadSystemStatus;
  if (typeof window.loadTotpStatus === 'function') window.TrueID.loadTotpStatus = window.loadTotpStatus;
  if (typeof window.openSecurityModal === 'function') window.TrueID.openSecurityModal = window.openSecurityModal;
  if (typeof window.quickAddTag === 'function') window.TrueID.quickAddTag = window.quickAddTag;
  if (typeof window.regenBackupCodes === 'function') window.TrueID.regenBackupCodes = window.regenBackupCodes;
  if (typeof window.renderAuditPaging === 'function') window.TrueID.renderAuditPaging = window.renderAuditPaging;
  if (typeof window.renderAuditTable === 'function') window.TrueID.renderAuditTable = window.renderAuditTable;
  if (typeof window.runRetentionNow === 'function') window.TrueID.runRetentionNow = window.runRetentionNow;
  if (typeof window.saveAdminSecurityPolicy === 'function') window.TrueID.saveAdminSecurityPolicy = window.saveAdminSecurityPolicy;
  if (typeof window.saveRetentionPolicy === 'function') window.TrueID.saveRetentionPolicy = window.saveRetentionPolicy;
  if (typeof window.startTotpSetup === 'function') window.TrueID.startTotpSetup = window.startTotpSetup;
  if (typeof window.terminateAdminSession === 'function') window.TrueID.terminateAdminSession = window.terminateAdminSession;
  if (typeof window.verifyTotpSetup === 'function') window.TrueID.verifyTotpSetup = window.verifyTotpSetup;
})();
