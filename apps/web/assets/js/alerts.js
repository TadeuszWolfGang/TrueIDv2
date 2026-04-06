/* Alerts module. */

var SOURCE_DOWN_DEFAULT_SILENCE_SECONDS = 300;
var SOURCE_DOWN_MIN_SILENCE_SECONDS = 60;
var SOURCE_DOWN_MAX_SILENCE_SECONDS = 3600;
var alertRulesCache = [];

function isSourceDownRuleType(ruleType) {
  return ruleType === 'source_down';
}

function updateAlertRuleConditionalFields() {
  var ruleType = document.getElementById('rule-type').value;
  var sourceDownFields = document.getElementById('source-down-fields');
  var silenceInput = document.getElementById('rule-source-down-silence');

  if (isSourceDownRuleType(ruleType)) {
    sourceDownFields.style.display = 'flex';
    if (!silenceInput.value) {
      silenceInput.value = String(SOURCE_DOWN_DEFAULT_SILENCE_SECONDS);
    }
    return;
  }

  sourceDownFields.style.display = 'none';
}

function setAlertRuleFormMode(isEditing) {
  document.getElementById('alert-rule-form-title').textContent = isEditing
    ? 'Edit alert rule'
    : 'Create alert rule';
  document.getElementById('alert-rule-save-btn').textContent = isEditing ? 'Update' : 'Create';
}

function resetAlertRuleForm() {
  document.getElementById('rule-name').value = '';
  document.getElementById('rule-type').value = 'new_mac';
  document.getElementById('rule-severity').value = 'warning';
  document.getElementById('rule-cooldown').value = '300';
  document.getElementById('rule-webhook').value = '';
  document.getElementById('rule-source-down-source').value = 'RADIUS';
  document.getElementById('rule-source-down-silence').value = String(SOURCE_DOWN_DEFAULT_SILENCE_SECONDS);
  document.getElementById('rule-channel-list').innerHTML = '<span class="muted">Loading channels...</span>';
  setAlertRuleFormMode(false);
  updateAlertRuleConditionalFields();
}

function parseSourceDownConditions(raw) {
  if (!raw) return null;
  try {
    var parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object') return null;
    return {
      source: parsed.source || 'RADIUS',
      silence_seconds: parsed.silence_seconds != null
        ? parseInt(parsed.silence_seconds, 10)
        : SOURCE_DOWN_DEFAULT_SILENCE_SECONDS
    };
  } catch (err) {
    return null;
  }
}

function formatAlertRuleTypeCell(rule) {
  var html = escapeHtml(rule.rule_type);
  if (!isSourceDownRuleType(rule.rule_type)) return html;

  var conditions = parseSourceDownConditions(rule.conditions);
  if (!conditions) {
    return html + '<div class="muted" style="margin-top:4px;">invalid conditions</div>';
  }

  return html +
    '<div class="muted" style="margin-top:4px;">' +
    escapeHtml(conditions.source) + ' · ' + escapeHtml(String(conditions.silence_seconds)) + 's' +
    '</div>';
}

function buildAlertRuleConditionsPayload(ruleType) {
  if (!isSourceDownRuleType(ruleType)) return null;

  var source = document.getElementById('rule-source-down-source').value;
  var silenceSeconds = parseInt(
    document.getElementById('rule-source-down-silence').value || String(SOURCE_DOWN_DEFAULT_SILENCE_SECONDS),
    10
  );

  if (!source) {
    throw new Error('Source adapter is required for Source Down rules.');
  }
  if (
    isNaN(silenceSeconds) ||
    silenceSeconds < SOURCE_DOWN_MIN_SILENCE_SECONDS ||
    silenceSeconds > SOURCE_DOWN_MAX_SILENCE_SECONDS
  ) {
    throw new Error('Silence window must be between 60 and 3600 seconds.');
  }

  return JSON.stringify({
    source: source,
    silence_seconds: silenceSeconds
  });
}

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
        resetAlertRuleForm();
        document.getElementById('alert-rule-form').style.display = '';
        loadRuleChannelOptions([]);
      }

      function hideRuleForm() {
        editingRuleId = null;
        resetAlertRuleForm();
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
          alertRulesCache = data.rules || [];
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
              '<td>' + formatAlertRuleTypeCell(r) + '</td>' +
              '<td><span class="' + badgeClass(r.severity) + '">' + escapeHtml(r.severity) + '</span></td>' +
              '<td>' + (r.action_webhook_url ? '<span class="muted">configured</span>' : '<span class="muted">none</span>') +
                (channels ? '<div class="muted" style="margin-top:4px;">' + escapeHtml(channels) + '</div>' : '') + '</td>' +
              '<td>' + escapeHtml(r.cooldown_seconds) + 's</td>' +
              '<td>' +
                '<button class="btn btn-sm" onclick="editAlertRule(' + r.id + ')">Edit</button> ' +
                '<button class="btn btn-sm" onclick="deleteAlertRule(' + r.id + ')">Delete</button>' +
              '</td>' +
              '</tr>';
          }).join('');
          applySortHeaders('alerts-rules-table', 'alertRules', null, loadAlertRules);
        } catch (err) {
          alertRulesCache = [];
          document.getElementById('rules-body').innerHTML =
            '<tr><td colspan="7" class="muted">No data available.</td></tr>';
        }
      }

      async function editAlertRule(id) {
        var rule = alertRulesCache.find(function (item) { return item.id === id; });
        if (!rule) {
          await loadAlertRules();
          rule = alertRulesCache.find(function (item) { return item.id === id; });
        }
        if (!rule) {
          alert('Edit failed: rule not found.');
          return;
        }

        editingRuleId = id;
        resetAlertRuleForm();
        setAlertRuleFormMode(true);
        document.getElementById('rule-name').value = rule.name || '';
        document.getElementById('rule-type').value = rule.rule_type || 'new_mac';
        document.getElementById('rule-severity').value = rule.severity || 'warning';
        document.getElementById('rule-cooldown').value = String(rule.cooldown_seconds != null ? rule.cooldown_seconds : 300);
        document.getElementById('rule-webhook').value = rule.action_webhook_url || '';
        updateAlertRuleConditionalFields();

        if (isSourceDownRuleType(rule.rule_type)) {
          var conditions = parseSourceDownConditions(rule.conditions);
          if (conditions) {
            document.getElementById('rule-source-down-source').value = conditions.source;
            document.getElementById('rule-source-down-silence').value = String(conditions.silence_seconds);
          }
        }

        loadRuleChannelOptions(
          Array.isArray(rule.channels)
            ? rule.channels.map(function (channel) { return channel.id; })
            : []
        );
        document.getElementById('alert-rule-form').style.display = '';
      }

      async function saveAlertRule() {
        var selectedChannelIds = Array.from(document.querySelectorAll('.rule-channel-cb:checked'))
          .map(function (el) { return parseInt(el.value, 10); })
          .filter(function (v) { return !isNaN(v); });
        var ruleType = document.getElementById('rule-type').value;
        try {
          var payload = {
            name: document.getElementById('rule-name').value.trim(),
            rule_type: ruleType,
            severity: document.getElementById('rule-severity').value,
            conditions: buildAlertRuleConditionsPayload(ruleType),
            action_webhook_url: document.getElementById('rule-webhook').value.trim() || null,
            action_webhook_headers: null,
            action_log: true,
            cooldown_seconds: parseInt(document.getElementById('rule-cooldown').value || '300', 10),
            channel_ids: selectedChannelIds
          };
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
  if (typeof window.editAlertRule === 'function') window.TrueID.editAlertRule = window.editAlertRule;
  if (typeof window.hideRuleForm === 'function') window.TrueID.hideRuleForm = window.hideRuleForm;
  if (typeof window.loadAlertHistory === 'function') window.TrueID.loadAlertHistory = window.loadAlertHistory;
  if (typeof window.loadAlertRules === 'function') window.TrueID.loadAlertRules = window.loadAlertRules;
  if (typeof window.loadAlertStats === 'function') window.TrueID.loadAlertStats = window.loadAlertStats;
  if (typeof window.loadRuleChannelOptions === 'function') window.TrueID.loadRuleChannelOptions = window.loadRuleChannelOptions;
  if (typeof window.renderAlertHistoryPaging === 'function') window.TrueID.renderAlertHistoryPaging = window.renderAlertHistoryPaging;
  if (typeof window.resetAlertRuleForm === 'function') window.TrueID.resetAlertRuleForm = window.resetAlertRuleForm;
  if (typeof window.saveAlertRule === 'function') window.TrueID.saveAlertRule = window.saveAlertRule;
  if (typeof window.showAddRuleForm === 'function') window.TrueID.showAddRuleForm = window.showAddRuleForm;
  if (typeof window.updateAlertRuleConditionalFields === 'function') window.TrueID.updateAlertRuleConditionalFields = window.updateAlertRuleConditionalFields;
  if (typeof window.toggleRuleEnabled === 'function') window.TrueID.toggleRuleEnabled = window.toggleRuleEnabled;
})();
