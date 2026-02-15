/* Alerts module. */

async function loadAlertStats() {
        try {
          var res = await fetch('/api/v2/alerts/stats', { credentials: 'include' });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          var s = await res.json();
          var critical = (s.by_severity_24h && s.by_severity_24h.critical) || 0;
          var warning = (s.by_severity_24h && s.by_severity_24h.warning) || 0;
          var success = Math.round((s.webhook_success_rate_24h || 0) * 100);
          document.getElementById('alerts-stats').innerHTML =
            '<span>Rules: <strong>' + (s.total_rules || 0) + '</strong> (' + (s.enabled_rules || 0) + ' enabled)</span>' +
            '<span>Fired 24h: <strong>' + (s.total_fired_24h || 0) + '</strong></span>' +
            '<span>Critical: <strong>' + critical + '</strong></span>' +
            '<span>Warning: <strong>' + warning + '</strong></span>' +
            '<span>Webhook success: <strong>' + success + '%</strong></span>';
        } catch (e) {
          document.getElementById('alerts-stats').innerHTML = '<span class="muted">No data available.</span>';
        }
      }

      /**
       * Sorts in-memory rows using tab sort state.
       * Parameters: tabName - sort key namespace, rows - mutable row list.
       * Returns: sorted row list.
       */
      function sortRowsByState(tabName, rows) {
        var state = window.sortState && window.sortState[tabName];
        if (!state || !state.column) return rows;
        var dir = state.direction === 'desc' ? -1 : 1;
        return rows.slice().sort(function (a, b) {
          var av = a[state.column];
          var bv = b[state.column];
          if (av == null && bv == null) return 0;
          if (av == null) return -1 * dir;
          if (bv == null) return 1 * dir;
          if (typeof av === 'number' && typeof bv === 'number') return (av - bv) * dir;
          return String(av).localeCompare(String(bv)) * dir;
        });
      }

      function showAddRuleForm() {
        editingRuleId = null;
        document.getElementById('alert-rule-form').style.display = '';
        loadRuleChannelOptions([]);
      }

      function hideRuleForm() {
        editingRuleId = null;
        document.getElementById('alert-rule-form').style.display = 'none';
      }

      async function loadRuleChannelOptions(selected) {
        if (!currentUser || currentUser.role !== 'Admin') return;
        selected = selected || [];
        var selectedMap = {};
        selected.forEach(function (id) { selectedMap[String(id)] = true; });
        try {
          var res = await fetch('/api/v2/notifications/channels', { credentials: 'include' });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          var channels = await res.json();
          var html = channels.map(function (c) {
            var checked = selectedMap[String(c.id)] ? 'checked' : '';
            return '<label class="setting-desc" style="display:inline-flex;align-items:center;gap:6px;margin-right:12px;">' +
              '<input type="checkbox" class="rule-channel-cb" value="' + c.id + '" ' + checked + '>' +
              escapeHtml(c.name) + ' (' + escapeHtml(c.channel_type) + ')' +
              '</label>';
          }).join('');
          document.getElementById('rule-channel-list').innerHTML = html || '<span class="muted">No channels configured.</span>';
        } catch (e) {
          document.getElementById('rule-channel-list').innerHTML = '<span class="muted">Failed to load channels.</span>';
        }
      }

      async function loadAlertRules() {
        if (!currentUser || currentUser.role !== 'Admin') return;
        try {
          var res = await fetch('/api/v2/alerts/rules', { credentials: 'include' });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          var data = await res.json();
          var rules = sortRowsByState('alertRules', data.rules || []);
          var body = document.getElementById('rules-body');
          if (!rules.length) {
            body.innerHTML = '<tr><td colspan="7" class="muted">No rules configured.</td></tr>';
            return;
          }
          body.innerHTML = rules.map(function (r) {
            var channels = Array.isArray(r.channels) ? r.channels.map(function (c) { return c.name; }).join(', ') : '';
            return '<tr>' +
              '<td><label class="toggle"><input type="checkbox" ' + (r.enabled ? 'checked' : '') + ' onchange="toggleRuleEnabled(' + r.id + ', this.checked)"><span class="toggle-slider"></span></label></td>' +
              '<td>' + escapeHtml(r.name) + '</td>' +
              '<td>' + escapeHtml(r.rule_type) + '</td>' +
              '<td><span class="' + badgeClass(r.severity) + '">' + escapeHtml(r.severity) + '</span></td>' +
              '<td>' + (r.action_webhook_url ? '<span class="muted">configured</span>' : '<span class="muted">none</span>') +
                (channels ? '<div class="muted" style="margin-top:4px;">' + escapeHtml(channels) + '</div>' : '') + '</td>' +
              '<td>' + escapeHtml(r.cooldown_seconds) + 's</td>' +
              '<td><button class="btn btn-sm" onclick="deleteAlertRule(' + r.id + ')">Delete</button></td>' +
              '</tr>';
          }).join('');
          applySortHeaders('alerts-rules-table', 'alertRules', null, loadAlertRules);
        } catch (err) {
          document.getElementById('rules-body').innerHTML =
            '<tr><td colspan="7" class="muted">No data available.</td></tr>';
        }
      }

      async function saveAlertRule() {
        var selectedChannelIds = Array.from(document.querySelectorAll('.rule-channel-cb:checked'))
          .map(function (el) { return parseInt(el.value, 10); })
          .filter(function (v) { return !isNaN(v); });
        var payload = {
          name: document.getElementById('rule-name').value.trim(),
          rule_type: document.getElementById('rule-type').value,
          severity: document.getElementById('rule-severity').value,
          conditions: null,
          action_webhook_url: document.getElementById('rule-webhook').value.trim() || null,
          action_webhook_headers: null,
          action_log: true,
          cooldown_seconds: parseInt(document.getElementById('rule-cooldown').value || '300', 10),
          channel_ids: selectedChannelIds
        };
        try {
          var url = '/api/v2/alerts/rules';
          var method = 'POST';
          if (editingRuleId) {
            url = '/api/v2/alerts/rules/' + encodeURIComponent(editingRuleId);
            method = 'PUT';
          }
          var res = await fetch(url, {
            method: method,
            headers: mutHeaders(),
            credentials: 'include',
            body: JSON.stringify(payload)
          });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          hideRuleForm();
          document.getElementById('rule-name').value = '';
          document.getElementById('rule-webhook').value = '';
          document.getElementById('rule-cooldown').value = '300';
          document.getElementById('rule-channel-list').innerHTML = '<span class="muted">Loading channels...</span>';
          loadAlertRules();
          loadAlertStats();
        } catch (err) {
          alert('Save failed: ' + err.message);
        }
      }

      async function toggleRuleEnabled(id, enabled) {
        try {
          var res = await fetch('/api/v2/alerts/rules/' + encodeURIComponent(id), {
            method: 'PUT',
            headers: mutHeaders(),
            credentials: 'include',
            body: JSON.stringify({ enabled: enabled })
          });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          loadAlertRules();
          loadAlertStats();
        } catch (err) {
          alert('Update failed: ' + err.message);
        }
      }

      async function deleteAlertRule(id) {
        if (!confirm('Delete this rule?')) return;
        try {
          var res = await fetch('/api/v2/alerts/rules/' + encodeURIComponent(id), {
            method: 'DELETE',
            headers: mutHeaders(),
            credentials: 'include'
          });
          if (!res.ok && res.status !== 204) throw new Error('HTTP ' + res.status);
          loadAlertRules();
          loadAlertStats();
        } catch (err) {
          alert('Delete failed: ' + err.message);
        }
      }

      function renderAlertHistoryPaging(page, perPage, total) {
        var totalPages = Math.ceil(total / perPage) || 1;
        var el = document.getElementById('alert-history-paging');
        var html = 'Page ' + page + ' of ' + totalPages + ' (' + total + ' alerts) &nbsp;';
        if (page > 1) html += '<button class="btn btn-sm" onclick="loadAlertHistory(' + (page - 1) + ')">← Prev</button> ';
        if (page < totalPages) html += '<button class="btn btn-sm" onclick="loadAlertHistory(' + (page + 1) + ')">Next →</button>';
        el.innerHTML = html;
      }

      async function loadAlertHistory(page) {
        alertHistoryCurrentPage = page || 1;
        var sev = document.getElementById('alert-hist-severity').value;
        var type = document.getElementById('alert-hist-type').value;
        var params = new URLSearchParams({ page: String(alertHistoryCurrentPage), limit: '50' });
        if (sev) params.set('severity', sev);
        if (type) params.set('rule_type', type);
        if (!window.sortState || !window.sortState.alertHistory || !window.sortState.alertHistory.column) {
          params.set('sort', 'fired_at');
          params.set('order', 'desc');
        }
        var sortParams = getSortParams('alertHistory');
        if (sortParams) {
          var sortQuery = new URLSearchParams(sortParams.slice(1));
          sortQuery.forEach(function (value, key) { params.set(key, value); });
        }

        try {
          var res = await fetch('/api/v2/alerts/history?' + params.toString(), { credentials: 'include' });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          var data = await res.json();
          var rows = sortRowsByState('alertHistory', data.data || []);
          var body = document.getElementById('alert-history-body');
          if (!rows.length) {
            body.innerHTML = '<tr><td colspan="7" class="muted">No data available.</td></tr>';
          } else {
            body.innerHTML = rows.map(function (r) {
              return '<tr>' +
                '<td><span class="' + badgeClass(r.severity) + '">' + escapeHtml(r.severity) + '</span></td>' +
                '<td>' + escapeHtml(r.rule_name) + '</td>' +
                '<td>' + escapeHtml(r.rule_type) + '</td>' +
                '<td>' + (r.ip ? '<a href="#" class="ip-link" onclick="openTimeline(\'ip\', \'' + escJs(r.ip) + '\');return false;">' + escapeHtml(r.ip) + '</a>' : '-') + '</td>' +
                '<td>' + escapeHtml(r.user_name || '-') + '</td>' +
                '<td>' + webhookStatusView(r.webhook_status) + '</td>' +
                '<td>' + escapeHtml(new Date(r.fired_at).toLocaleString()) + '</td>' +
                '</tr>';
            }).join('');
          }
          applySortHeaders('alert-history-table', 'alertHistory', null, loadAlertHistory);
          renderAlertHistoryPaging(data.page || alertHistoryCurrentPage, data.limit || 50, data.total || 0);
        } catch (err) {
          document.getElementById('alert-history-body').innerHTML =
            '<tr><td colspan="7" class="muted">No data available.</td></tr>';
          document.getElementById('alert-history-paging').innerHTML = '';
        }
      }

(function () {
  window.TrueID = window.TrueID || {};
  if (typeof window.deleteAlertRule === 'function') window.TrueID.deleteAlertRule = window.deleteAlertRule;
  if (typeof window.hideRuleForm === 'function') window.TrueID.hideRuleForm = window.hideRuleForm;
  if (typeof window.loadAlertHistory === 'function') window.TrueID.loadAlertHistory = window.loadAlertHistory;
  if (typeof window.loadAlertRules === 'function') window.TrueID.loadAlertRules = window.loadAlertRules;
  if (typeof window.loadAlertStats === 'function') window.TrueID.loadAlertStats = window.loadAlertStats;
  if (typeof window.loadRuleChannelOptions === 'function') window.TrueID.loadRuleChannelOptions = window.loadRuleChannelOptions;
  if (typeof window.renderAlertHistoryPaging === 'function') window.TrueID.renderAlertHistoryPaging = window.renderAlertHistoryPaging;
  if (typeof window.saveAlertRule === 'function') window.TrueID.saveAlertRule = window.saveAlertRule;
  if (typeof window.showAddRuleForm === 'function') window.TrueID.showAddRuleForm = window.showAddRuleForm;
  if (typeof window.toggleRuleEnabled === 'function') window.TrueID.toggleRuleEnabled = window.toggleRuleEnabled;
})();
