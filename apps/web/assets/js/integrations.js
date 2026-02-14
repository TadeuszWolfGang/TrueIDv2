/* Integrations module (notifications, firewall, SIEM, LDAP, Sycope). */

function showNotificationForm() {
        notificationEditingId = null;
        document.getElementById('notification-form').style.display = '';
        document.getElementById('notif-name').value = '';
        document.getElementById('notif-type').value = 'email';
        document.getElementById('notif-enabled').checked = true;
        renderNotificationConfigForm();
      }

      function hideNotificationForm() {
        notificationEditingId = null;
        document.getElementById('notification-form').style.display = 'none';
      }

      function renderNotificationConfigForm() {
        var type = document.getElementById('notif-type').value;
        var el = document.getElementById('notif-config-fields');
        if (type === 'email') {
          el.innerHTML =
            '<input id="notif-smtp-host" class="setting-input" style="width:180px;" placeholder="SMTP host">' +
            '<input id="notif-smtp-port" class="setting-input" style="width:120px;" type="number" value="587" placeholder="Port">' +
            '<label class="setting-desc" style="display:flex;align-items:center;gap:6px;"><input id="notif-smtp-tls" type="checkbox" checked> STARTTLS</label>' +
            '<input id="notif-smtp-user" class="setting-input" style="width:180px;" placeholder="SMTP user (optional)">' +
            '<input id="notif-smtp-pass" class="setting-input" style="width:180px;" type="password" placeholder="SMTP pass (optional)">' +
            '<input id="notif-from" class="setting-input" style="width:220px;" placeholder="From address">' +
            '<input id="notif-to" class="setting-input" style="width:280px;" placeholder="Recipients (comma separated)">';
        } else if (type === 'slack') {
          el.innerHTML =
            '<input id="notif-webhook-url" class="setting-input" style="width:420px;" placeholder="https://hooks.slack.com/...">' +
            '<input id="notif-channel" class="setting-input" style="width:160px;" placeholder="#channel (optional)">' +
            '<input id="notif-username" class="setting-input" style="width:140px;" placeholder="Username (optional)">' +
            '<input id="notif-icon-emoji" class="setting-input" style="width:140px;" placeholder=":shield: (optional)">';
        } else if (type === 'teams') {
          el.innerHTML = '<input id="notif-webhook-url" class="setting-input" style="width:520px;" placeholder="Teams webhook URL">';
        } else {
          el.innerHTML =
            '<input id="notif-webhook-url" class="setting-input" style="width:360px;" placeholder="http(s)://...">' +
            '<select id="notif-webhook-method" class="setting-input" style="width:110px;"><option value="POST">POST</option><option value="PUT">PUT</option></select>';
        }
      }

      function buildNotificationConfigPayload() {
        var type = document.getElementById('notif-type').value;
        if (type === 'email') {
          return {
            smtp_host: document.getElementById('notif-smtp-host').value.trim(),
            smtp_port: parseInt(document.getElementById('notif-smtp-port').value || '587', 10),
            smtp_tls: document.getElementById('notif-smtp-tls').checked,
            smtp_user: document.getElementById('notif-smtp-user').value.trim() || null,
            smtp_pass: document.getElementById('notif-smtp-pass').value.trim() || null,
            from_address: document.getElementById('notif-from').value.trim(),
            to_addresses: (document.getElementById('notif-to').value || '').split(',').map(function (v) { return v.trim(); }).filter(function (v) { return v.length > 0; }),
            subject_prefix: '[TrueID Alert]'
          };
        }
        if (type === 'slack') {
          return {
            webhook_url: document.getElementById('notif-webhook-url').value.trim(),
            channel: (document.getElementById('notif-channel').value || '').trim() || null,
            username: (document.getElementById('notif-username').value || '').trim() || null,
            icon_emoji: (document.getElementById('notif-icon-emoji').value || '').trim() || null
          };
        }
        if (type === 'teams') {
          return { webhook_url: document.getElementById('notif-webhook-url').value.trim() };
        }
        return {
          url: document.getElementById('notif-webhook-url').value.trim(),
          method: document.getElementById('notif-webhook-method').value,
          headers: null
        };
      }

      async function saveNotificationChannel() {
        var payload = {
          name: document.getElementById('notif-name').value.trim(),
          channel_type: document.getElementById('notif-type').value,
          enabled: document.getElementById('notif-enabled').checked,
          config: buildNotificationConfigPayload()
        };
        var url = '/api/v2/notifications/channels';
        var method = 'POST';
        if (notificationEditingId) {
          url = '/api/v2/notifications/channels/' + encodeURIComponent(notificationEditingId);
          method = 'PUT';
        }
        try {
          var res = await fetch(url, {
            method: method,
            headers: mutHeaders(),
            credentials: 'include',
            body: JSON.stringify(payload)
          });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          hideNotificationForm();
          loadNotificationsTab();
        } catch (e) {
          alert('Save failed: ' + e.message);
        }
      }

      async function testNotificationChannel(id) {
        try {
          var res = await fetch('/api/v2/notifications/channels/' + encodeURIComponent(id) + '/test', {
            method: 'POST',
            headers: mutHeaders(),
            credentials: 'include',
            body: JSON.stringify({})
          });
          var body = await res.json().catch(function () { return {}; });
          if (!res.ok || body.success === false) throw new Error(body.error || ('HTTP ' + res.status));
          alert('Test sent successfully.');
        } catch (e) {
          alert('Test failed: ' + e.message);
        }
      }

      async function deleteNotificationChannel(id) {
        if (!confirm('Delete this channel?')) return;
        try {
          var res = await fetch('/api/v2/notifications/channels/' + encodeURIComponent(id), {
            method: 'DELETE',
            headers: mutHeaders(),
            credentials: 'include'
          });
          if (!res.ok && res.status !== 204) throw new Error('HTTP ' + res.status);
          loadNotificationsTab();
        } catch (e) {
          alert('Delete failed: ' + e.message);
        }
      }

      async function loadChannelDeliveries(id) {
        try {
          var res = await fetch('/api/v2/notifications/channels/' + encodeURIComponent(id) + '/deliveries', { credentials: 'include' });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          var rows = await res.json();
          if (!Array.isArray(rows) || !rows.length) {
            document.getElementById('notifications-deliveries').innerHTML = 'No deliveries yet.';
            return;
          }
          var html = '<table><thead><tr><th>Status</th><th>Alert</th><th>Error</th><th>Time</th></tr></thead><tbody>';
          html += rows.map(function (r) {
            var cls = r.status === 'sent' ? 'check-yes' : 'check-no';
            return '<tr><td><span class="' + cls + '">' + escapeHtml(r.status) + '</span></td><td>' +
              escapeHtml(r.alert_rule_name || '-') + '</td><td>' + escapeHtml(r.error_message || '-') +
              '</td><td>' + escapeHtml(new Date(r.delivered_at).toLocaleString()) + '</td></tr>';
          }).join('');
          html += '</tbody></table>';
          document.getElementById('notifications-deliveries').innerHTML = html;
        } catch (e) {
          document.getElementById('notifications-deliveries').innerHTML = 'Failed to load deliveries.';
        }
      }

      async function loadNotificationsTab() {
        if (!currentUser || currentUser.role !== 'Admin') return;
        try {
          var res = await fetch('/api/v2/notifications/channels', { credentials: 'include' });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          var rows = await res.json();
          var body = document.getElementById('notifications-body');
          if (!Array.isArray(rows) || !rows.length) {
            body.innerHTML = '<tr><td colspan="5" class="muted">No channels configured.</td></tr>';
            document.getElementById('notifications-deliveries').innerHTML = 'No deliveries yet.';
            return;
          }
          body.innerHTML = rows.map(function (c) {
            return '<tr>' +
              '<td>' + escapeHtml(c.name) + '</td>' +
              '<td><span class="badge badge-info">' + escapeHtml(c.channel_type) + '</span></td>' +
              '<td>' + (c.enabled ? '<span class="check-yes">enabled</span>' : '<span class="check-no">disabled</span>') + '</td>' +
              '<td>' + escapeHtml(c.config_summary || '-') + '</td>' +
              '<td><button class="btn btn-sm" onclick="testNotificationChannel(' + c.id + ')">Test</button> ' +
              '<button class="btn btn-sm" onclick="loadChannelDeliveries(' + c.id + ')">Deliveries</button> ' +
              '<button class="btn btn-sm role-admin" onclick="deleteNotificationChannel(' + c.id + ')">Delete</button></td>' +
              '</tr>';
          }).join('');
          loadChannelDeliveries(rows[0].id);
        } catch (e) {
          document.getElementById('notifications-body').innerHTML = '<tr><td colspan="5" class="muted">No data available.</td></tr>';
        }
      }

      function firewallTypeBadge(raw) {
        var type = (raw || '').toLowerCase();
        if (type === 'panos') return '<span class="badge badge-panos">PAN-OS</span>';
        if (type === 'fortigate') return '<span class="badge badge-fortigate">FortiGate</span>';
        return '<span class="badge badge-info">' + escapeHtml(raw || '-') + '</span>';
      }

      function toggleFirewallUsername() {
        var type = document.getElementById('fw-type').value;
        document.getElementById('fw-username').style.display = type === 'panos' ? '' : 'none';
      }

      function showFirewallForm(item) {
        firewallEditingId = item && item.id ? item.id : null;
        document.getElementById('firewall-form-wrap').style.display = '';
        document.getElementById('fw-name').value = item ? (item.name || '') : '';
        document.getElementById('fw-type').value = item ? (item.firewall_type || 'panos') : 'panos';
        document.getElementById('fw-host').value = item ? (item.host || '') : '';
        document.getElementById('fw-port').value = item ? (item.port || 443) : 443;
        document.getElementById('fw-interval').value = item ? (item.push_interval_secs || 60) : 60;
        document.getElementById('fw-username').value = item ? (item.username || '') : '';
        document.getElementById('fw-password').value = '';
        document.getElementById('fw-subnet-filter').value = item ? (item.subnet_filter || '') : '';
        document.getElementById('fw-verify-tls').checked = item ? !!item.verify_tls : false;
        document.getElementById('fw-enabled').checked = item ? !!item.enabled : true;
        toggleFirewallUsername();
      }

      function hideFirewallForm() {
        firewallEditingId = null;
        document.getElementById('firewall-form-wrap').style.display = 'none';
      }

      async function saveFirewallTarget() {
        if (!currentUser || currentUser.role !== 'Admin') return;
        var payload = {
          name: document.getElementById('fw-name').value.trim(),
          firewall_type: document.getElementById('fw-type').value,
          host: document.getElementById('fw-host').value.trim(),
          port: parseInt(document.getElementById('fw-port').value || '443', 10),
          username: document.getElementById('fw-username').value.trim() || null,
          verify_tls: document.getElementById('fw-verify-tls').checked,
          push_interval_secs: parseInt(document.getElementById('fw-interval').value || '60', 10),
          subnet_filter: document.getElementById('fw-subnet-filter').value.trim() || null,
          enabled: document.getElementById('fw-enabled').checked
        };
        var pass = document.getElementById('fw-password').value.trim();
        if (!firewallEditingId || pass) payload.password = pass;
        var url = '/api/v2/firewall/targets';
        var method = 'POST';
        if (firewallEditingId) {
          url = '/api/v2/firewall/targets/' + encodeURIComponent(firewallEditingId);
          method = 'PUT';
        }
        try {
          var res = await fetch(url, {
            method: method,
            headers: mutHeaders(),
            credentials: 'include',
            body: JSON.stringify(payload)
          });
          if (!res.ok) {
            var txt = await res.text();
            throw new Error('HTTP ' + res.status + ' ' + txt);
          }
          hideFirewallForm();
          await loadFirewallTargets();
        } catch (e) {
          alert('Save failed: ' + e.message);
        }
      }

      async function loadFirewallTab() {
        await loadFirewallTargets();
        await loadFirewallStats();
      }

      async function loadFirewallStats() {
        try {
          var res = await fetch('/api/v2/firewall/stats', { credentials: 'include' });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          var s = await res.json();
          var lastPushAt = '-';
          for (var i = 0; i < firewallTargets.length; i += 1) {
            var lp = firewallTargets[i].last_push_at;
            if (!lp) continue;
            if (lastPushAt === '-' || new Date(lp).getTime() > new Date(lastPushAt).getTime()) lastPushAt = lp;
          }
          document.getElementById('firewall-stats').innerHTML =
            '<span>Total targets: <strong>' + (s.total_targets || 0) + '</strong></span>' +
            '<span>Enabled: <strong>' + (s.enabled_targets || 0) + '</strong></span>' +
            '<span>Last push: <strong>' + escapeHtml(lastPushAt === '-' ? '-' : timeAgo(lastPushAt)) + '</strong></span>';
        } catch (e) {
          document.getElementById('firewall-stats').innerHTML = '<span class="muted">No stats available.</span>';
        }
      }

      async function loadFirewallTargets() {
        try {
          var res = await fetch('/api/v2/firewall/targets', { credentials: 'include' });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          firewallTargets = await res.json();
          var body = document.getElementById('firewall-body');
          if (!Array.isArray(firewallTargets) || !firewallTargets.length) {
            body.innerHTML = '<tr><td colspan="7" class="muted">No targets configured.</td></tr>';
            loadFirewallStats();
            return;
          }
          body.innerHTML = firewallTargets.map(function (t) {
            var id = t.id;
            var open = !!firewallHistoryOpen[id];
            var actions =
              '<button class="btn btn-sm role-admin" onclick="event.stopPropagation();testFirewallTarget(' + id + ')">Test</button> ' +
              '<button class="btn btn-sm role-admin" onclick="event.stopPropagation();forceFirewallPush(' + id + ')">Force Push</button> ' +
              '<button class="btn btn-sm role-admin" onclick="event.stopPropagation();editFirewallTarget(' + id + ')">Edit</button> ' +
              '<button class="btn btn-sm role-admin" onclick="event.stopPropagation();deleteFirewallTarget(' + id + ')">Delete</button>';
            return '<tr class="expand-row" onclick="toggleFirewallHistory(' + id + ')">' +
              '<td>' + escapeHtml(t.name || '-') + '<div id="fw-result-' + id + '" class="muted" style="font-size:11px;"></div></td>' +
              '<td>' + firewallTypeBadge(t.firewall_type) + '</td>' +
              '<td>' + escapeHtml((t.host || '-') + ':' + (t.port || '-')) + '</td>' +
              '<td>' + escapeHtml((t.push_interval_secs || '-') + 's') + '</td>' +
              '<td>' + escapeHtml(t.last_push_status || '-') + '</td>' +
              '<td>' + escapeHtml(timeAgo(t.last_push_at)) + '</td>' +
              '<td>' + actions + '</td>' +
              '</tr>' +
              '<tr id="fw-history-row-' + id + '" style="display:' + (open ? '' : 'none') + ';"><td colspan="7"><div id="fw-history-' + id + '" class="muted">Loading history...</div></td></tr>';
          }).join('');
          applyRoleVisibility(currentUser.role);
          await loadFirewallStats();
          for (var k in firewallHistoryOpen) {
            if (firewallHistoryOpen[k]) loadFirewallHistory(parseInt(k, 10));
          }
        } catch (e) {
          document.getElementById('firewall-body').innerHTML =
            '<tr><td colspan="7" style="color:var(--status-error);">Failed: ' + escapeHtml(e.message) + '</td></tr>';
        }
      }

      function editFirewallTarget(id) {
        var item = firewallTargets.find(function (t) { return t.id === id; });
        if (item) showFirewallForm(item);
      }

      async function deleteFirewallTarget(id) {
        if (!currentUser || currentUser.role !== 'Admin') return;
        if (!confirm('Delete firewall target #' + id + '?')) return;
        try {
          var res = await fetch('/api/v2/firewall/targets/' + encodeURIComponent(id), {
            method: 'DELETE',
            headers: mutHeaders(),
            credentials: 'include'
          });
          if (!res.ok && res.status !== 204) throw new Error('HTTP ' + res.status);
          await loadFirewallTargets();
        } catch (e) {
          alert('Delete failed: ' + e.message);
        }
      }

      async function testFirewallTarget(id) {
        if (!currentUser || currentUser.role !== 'Admin') return;
        try {
          var res = await fetch('/api/v2/firewall/targets/' + encodeURIComponent(id) + '/test', {
            method: 'POST',
            headers: mutHeaders(),
            credentials: 'include'
          });
          var data = await res.json();
          var el = document.getElementById('fw-result-' + id);
          if (res.ok && data.status === 'ok') {
            el.textContent = 'Connection test: OK';
            el.style.color = 'var(--status-ok)';
          } else {
            el.textContent = 'Connection test: ' + (data.message || ('HTTP ' + res.status));
            el.style.color = 'var(--status-error)';
          }
        } catch (e) {
          var el2 = document.getElementById('fw-result-' + id);
          el2.textContent = 'Connection test failed: ' + e.message;
          el2.style.color = 'var(--status-error)';
        }
      }

      async function forceFirewallPush(id) {
        if (!currentUser || currentUser.role !== 'Admin') return;
        try {
          var res = await fetch('/api/v2/firewall/targets/' + encodeURIComponent(id) + '/push', {
            method: 'POST',
            headers: mutHeaders(),
            credentials: 'include'
          });
          var data = await res.json();
          var el = document.getElementById('fw-result-' + id);
          if (res.ok) {
            el.textContent = 'Push initiated: ' + (data.pushed_count || 0) + ' entries';
            el.style.color = 'var(--status-ok)';
          } else {
            el.textContent = 'Push failed: ' + (data.message || ('HTTP ' + res.status));
            el.style.color = 'var(--status-error)';
          }
          await loadFirewallTargets();
        } catch (e) {
          var el2 = document.getElementById('fw-result-' + id);
          el2.textContent = 'Push failed: ' + e.message;
          el2.style.color = 'var(--status-error)';
        }
      }

      function toggleFirewallHistory(id) {
        firewallHistoryOpen[id] = !firewallHistoryOpen[id];
        var row = document.getElementById('fw-history-row-' + id);
        if (!row) return;
        row.style.display = firewallHistoryOpen[id] ? '' : 'none';
        if (firewallHistoryOpen[id]) loadFirewallHistory(id);
      }

      async function loadFirewallHistory(id) {
        var box = document.getElementById('fw-history-' + id);
        if (!box) return;
        try {
          var res = await fetch('/api/v2/firewall/targets/' + encodeURIComponent(id) + '/history?limit=20&page=1', { credentials: 'include' });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          var data = await res.json();
          var rows = data.data || [];
          if (!rows.length) {
            box.innerHTML = '<span class="muted">No push history.</span>';
            return;
          }
          box.innerHTML = '<table><thead><tr><th>Timestamp</th><th>Entries</th><th>Status</th><th>Duration</th></tr></thead><tbody>' +
            rows.map(function (r) {
              return '<tr>' +
                '<td>' + escapeHtml(new Date(r.pushed_at).toLocaleString()) + '</td>' +
                '<td>' + escapeHtml(r.mapping_count != null ? r.mapping_count : '-') + '</td>' +
                '<td>' + escapeHtml(r.status || '-') + '</td>' +
                '<td>' + escapeHtml(r.duration_ms != null ? r.duration_ms + ' ms' : '-') + '</td>' +
                '</tr>';
            }).join('') +
            '</tbody></table>';
        } catch (e) {
          box.innerHTML = '<span style="color:var(--status-error);">Failed to load history: ' + escapeHtml(e.message) + '</span>';
        }
      }

      function siemFormatBadge(fmt) {
        var f = (fmt || '').toLowerCase();
        var cls = f === 'cef' ? 'badge-cef' : (f === 'leef' ? 'badge-leef' : 'badge-json');
        return '<span class="badge ' + cls + '">' + escapeHtml((fmt || '-').toUpperCase()) + '</span>';
      }

      function siemTransportBadge(tp) {
        var t = (tp || '').toLowerCase();
        var cls = t === 'udp' ? 'badge-udp' : 'badge-tcp';
        return '<span class="badge ' + cls + '">' + escapeHtml((tp || '-').toUpperCase()) + '</span>';
      }

      function showSiemForm(item) {
        siemEditingId = item && item.id ? item.id : null;
        document.getElementById('siem-form-wrap').style.display = '';
        document.getElementById('siem-name').value = item ? (item.name || '') : '';
        document.getElementById('siem-format').value = item ? (item.format || 'cef') : 'cef';
        document.getElementById('siem-transport').value = item ? (item.transport || 'udp') : 'udp';
        document.getElementById('siem-host').value = item ? (item.host || '') : '';
        document.getElementById('siem-port').value = item ? (item.port || 514) : 514;
        document.getElementById('siem-fwd-m').checked = item ? !!item.forward_mappings : true;
        document.getElementById('siem-fwd-c').checked = item ? !!item.forward_conflicts : true;
        document.getElementById('siem-fwd-a').checked = item ? !!item.forward_alerts : false;
        document.getElementById('siem-enabled').checked = item ? !!item.enabled : true;
      }

      function hideSiemForm() {
        siemEditingId = null;
        document.getElementById('siem-form-wrap').style.display = 'none';
      }

      async function saveSiemTarget() {
        if (!currentUser || currentUser.role !== 'Admin') return;
        var payload = {
          name: document.getElementById('siem-name').value.trim(),
          format: document.getElementById('siem-format').value,
          transport: document.getElementById('siem-transport').value,
          host: document.getElementById('siem-host').value.trim(),
          port: parseInt(document.getElementById('siem-port').value || '514', 10),
          forward_mappings: document.getElementById('siem-fwd-m').checked,
          forward_conflicts: document.getElementById('siem-fwd-c').checked,
          forward_alerts: document.getElementById('siem-fwd-a').checked,
          enabled: document.getElementById('siem-enabled').checked
        };
        var url = '/api/v2/siem/targets';
        var method = 'POST';
        if (siemEditingId) {
          url = '/api/v2/siem/targets/' + encodeURIComponent(siemEditingId);
          method = 'PUT';
        }
        try {
          var res = await fetch(url, {
            method: method,
            headers: mutHeaders(),
            credentials: 'include',
            body: JSON.stringify(payload)
          });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          hideSiemForm();
          await loadSiemTab();
        } catch (e) {
          alert('Save failed: ' + e.message);
        }
      }

      async function loadSiemTab() {
        await loadSiemStats();
        await loadSiemTargets();
      }

      async function loadSiemStats() {
        try {
          var res = await fetch('/api/v2/siem/stats', { credentials: 'include' });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          var s = await res.json();
          var forwarded = s.events_forwarded_total != null ? s.events_forwarded_total : (s.total_events_forwarded || 0);
          document.getElementById('siem-stats').innerHTML =
            '<span>Total targets: <strong>' + (s.total_targets || 0) + '</strong></span>' +
            '<span>Enabled: <strong>' + (s.enabled_targets || 0) + '</strong></span>' +
            '<span>Events forwarded total: <strong>' + forwarded + '</strong></span>';
        } catch (e) {
          document.getElementById('siem-stats').innerHTML = '<span class="muted">No stats available.</span>';
        }
      }

      async function loadSiemTargets() {
        try {
          var res = await fetch('/api/v2/siem/targets', { credentials: 'include' });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          siemTargets = await res.json();
          var body = document.getElementById('siem-body');
          if (!Array.isArray(siemTargets) || !siemTargets.length) {
            body.innerHTML = '<tr><td colspan="6" class="muted">No targets configured.</td></tr>';
            return;
          }
          body.innerHTML = siemTargets.map(function (t) {
            var flags =
              '<span class="' + (t.forward_mappings ? 'check-yes' : 'check-no') + '">M</span> ' +
              '<span class="' + (t.forward_conflicts ? 'check-yes' : 'check-no') + '">C</span> ' +
              '<span class="' + (t.forward_alerts ? 'check-yes' : 'check-no') + '">A</span>';
            return '<tr>' +
              '<td>' + escapeHtml(t.name || '-') + '</td>' +
              '<td>' + siemFormatBadge(t.format) + '</td>' +
              '<td>' + siemTransportBadge(t.transport) + '</td>' +
              '<td>' + escapeHtml((t.host || '-') + ':' + (t.port || '-')) + '</td>' +
              '<td>' + flags + '</td>' +
              '<td><button class="btn btn-sm role-admin" onclick="editSiemTarget(' + t.id + ')">Edit</button> ' +
              '<button class="btn btn-sm role-admin" onclick="deleteSiemTarget(' + t.id + ')">Delete</button></td>' +
              '</tr>';
          }).join('');
          applyRoleVisibility(currentUser.role);
        } catch (e) {
          document.getElementById('siem-body').innerHTML =
            '<tr><td colspan="6" style="color:var(--status-error);">Failed: ' + escapeHtml(e.message) + '</td></tr>';
        }
      }

      function editSiemTarget(id) {
        var item = siemTargets.find(function (t) { return t.id === id; });
        if (item) showSiemForm(item);
      }

      async function deleteSiemTarget(id) {
        if (!currentUser || currentUser.role !== 'Admin') return;
        if (!confirm('Delete SIEM target #' + id + '?')) return;
        try {
          var res = await fetch('/api/v2/siem/targets/' + encodeURIComponent(id), {
            method: 'DELETE',
            headers: mutHeaders(),
            credentials: 'include'
          });
          if (!res.ok && res.status !== 204) throw new Error('HTTP ' + res.status);
          await loadSiemTab();
        } catch (e) {
          alert('Delete failed: ' + e.message);
        }
      }

      async function loadLdapTab() {
        await loadLdapConfig();
        await loadLdapGroups();
      }

      async function loadLdapConfig() {
        try {
          var res = await fetch('/api/v2/ldap/config', { credentials: 'include' });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          var cfg = await res.json();
          document.getElementById('ldap-enabled').checked = !!cfg.enabled;
          document.getElementById('ldap-url').value = cfg.ldap_url || '';
          document.getElementById('ldap-bind-dn').value = cfg.bind_dn || '';
          document.getElementById('ldap-base-dn').value = cfg.base_dn || '';
          document.getElementById('ldap-filter').value = cfg.search_filter || '';
          document.getElementById('ldap-interval').value = cfg.sync_interval_secs || 300;
          var ps = document.getElementById('ldap-pass-status');
          ps.textContent = cfg.password_set ? 'Password saved' : 'Not set';
          ps.style.color = cfg.password_set ? 'var(--status-ok)' : 'var(--status-error)';
        } catch (e) {
          document.getElementById('ldap-sync-msg').textContent = 'Failed to load LDAP config: ' + e.message;
        }
      }

      async function saveLdapField(field, value, el) {
        if (!currentUser || currentUser.role !== 'Admin') return;
        var payload = {};
        payload[field] = value;
        try {
          var res = await fetch('/api/v2/ldap/config', {
            method: 'PUT',
            headers: mutHeaders(),
            credentials: 'include',
            body: JSON.stringify(payload)
          });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          flashElement(el, true);
        } catch (e) {
          flashElement(el, false);
        }
      }

      async function saveLdapPassword() {
        if (!currentUser || currentUser.role !== 'Admin') return;
        var input = document.getElementById('ldap-bind-pass');
        var pass = input.value.trim();
        if (!pass) return;
        try {
          var res = await fetch('/api/v2/ldap/config', {
            method: 'PUT',
            headers: mutHeaders(),
            credentials: 'include',
            body: JSON.stringify({ bind_password: pass })
          });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          input.value = '';
          var ps = document.getElementById('ldap-pass-status');
          ps.textContent = 'Password saved';
          ps.style.color = 'var(--status-ok)';
        } catch (e) {
          alert('Failed to save password: ' + e.message);
        }
      }

      async function forceLdapSync() {
        if (!currentUser || currentUser.role !== 'Admin') return;
        try {
          var res = await fetch('/api/v2/ldap/sync', {
            method: 'POST',
            headers: mutHeaders(),
            credentials: 'include'
          });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          document.getElementById('ldap-sync-msg').textContent = 'Sync initiated';
          document.getElementById('ldap-sync-msg').style.color = 'var(--status-ok)';
        } catch (e) {
          document.getElementById('ldap-sync-msg').textContent = 'Sync failed: ' + e.message;
          document.getElementById('ldap-sync-msg').style.color = 'var(--status-error)';
        }
      }

      async function loadLdapGroups() {
        try {
          var res = await fetch('/api/v2/ldap/groups', { credentials: 'include' });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          var rows = await res.json();
          var box = document.getElementById('ldap-groups-list');
          if (!Array.isArray(rows) || !rows.length) {
            box.innerHTML = '<span class="muted">No groups available.</span>';
            return;
          }
          box.innerHTML = rows.map(function (r) {
            var name = r.group_name || '-';
            return '<div style="margin:4px 0;"><a class="ip-link" href="#" onclick="loadLdapGroupMembers(\'' + escJs(name) + '\');return false;">' + escapeHtml(name) + '</a></div>';
          }).join('');
        } catch (e) {
          document.getElementById('ldap-groups-list').innerHTML = '<span style="color:var(--status-error);">Failed: ' + escapeHtml(e.message) + '</span>';
        }
      }

      async function loadLdapGroupMembers(group) {
        try {
          var res = await fetch('/api/v2/ldap/groups/' + encodeURIComponent(group) + '/members', { credentials: 'include' });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          var rows = await res.json();
          var box = document.getElementById('ldap-members-list');
          if (!Array.isArray(rows) || !rows.length) {
            box.innerHTML = '<span class="muted">No members in ' + escapeHtml(group) + '.</span>';
            return;
          }
          box.innerHTML = '<div class="muted" style="margin-bottom:6px;">Group: ' + escapeHtml(group) + '</div>' +
            rows.map(function (r) {
              return '<div style="margin:4px 0;">' + escapeHtml(r.username || '-') + '</div>';
            }).join('');
        } catch (e) {
          document.getElementById('ldap-members-list').innerHTML = '<span style="color:var(--status-error);">Failed: ' + escapeHtml(e.message) + '</span>';
        }
      }

      async function lookupLdapUserGroups() {
        var username = document.getElementById('ldap-user-query').value.trim();
        if (!username) return;
        try {
          var res = await fetch('/api/v2/ldap/users/' + encodeURIComponent(username) + '/groups', { credentials: 'include' });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          var rows = await res.json();
          var box = document.getElementById('ldap-user-groups');
          if (!Array.isArray(rows) || !rows.length) {
            box.innerHTML = '<span class="muted">No groups for ' + escapeHtml(username) + '.</span>';
            return;
          }
          box.innerHTML = rows.map(function (r) {
            return '<div style="margin:4px 0;">' + escapeHtml(r.group_name || '-') + '</div>';
          }).join('');
        } catch (e) {
          document.getElementById('ldap-user-groups').innerHTML = '<span style="color:var(--status-error);">Failed: ' + escapeHtml(e.message) + '</span>';
        }
      }

      async function loadSycopeConfig() {
        try {
          var res = await fetch('/api/v1/admin/config/sycope', { credentials: 'include' });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          var cfg = await res.json();

          document.getElementById('sycope-enabled').checked = cfg.enabled || false;
          document.getElementById('sycope-host').value = cfg.sycope_host || '';
          document.getElementById('sycope-login').value = cfg.sycope_login || '';
          document.getElementById('sycope-lookup').value = cfg.lookup_name || 'TrueID_Enrichment';
          document.getElementById('sycope-interval').value = cfg.sync_interval_seconds || 300;
          document.getElementById('sycope-evt-idx').checked = cfg.enable_event_index || false;
          document.getElementById('sycope-idx-name').value = cfg.index_name || 'trueid_events';

          var passStatus = document.getElementById('pass-status');
          if (cfg.sycope_pass_set) {
            passStatus.textContent = 'Password saved';
            passStatus.style.color = 'var(--status-ok)';
          } else {
            passStatus.textContent = 'Not set';
            passStatus.style.color = 'var(--status-error)';
          }

          renderSyncStatus(cfg.last_sync);
        } catch (err) {
          console.error('Failed to load Sycope config:', err);
          document.getElementById('sync-status').innerHTML =
            '<span style="color:var(--status-error);">Failed to load config: ' + err.message + '</span>';
        }
      }

      async function saveSycopeField(field, value) {
        var payload = {};
        payload[field] = value;
        try {
          var res = await fetch('/api/v1/admin/config/sycope', {
            method: 'PUT',
            headers: mutHeaders(),
            credentials: 'include',
            body: JSON.stringify(payload),
          });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          flashElement(event.target, true);
        } catch (err) {
          console.error('Save failed:', err);
          flashElement(event.target, false);
        }
      }

      async function saveSycopePassword() {
        var input = document.getElementById('sycope-pass');
        var val = input.value.trim();
        if (!val) return;
        try {
          var res = await fetch('/api/v1/admin/config/sycope', {
            method: 'PUT',
            headers: mutHeaders(),
            credentials: 'include',
            body: JSON.stringify({ sycope_pass: val }),
          });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          input.value = '';
          var passStatus = document.getElementById('pass-status');
          passStatus.textContent = 'Password saved';
          passStatus.style.color = 'var(--status-ok)';
        } catch (err) {
          console.error('Password save failed:', err);
          alert('Failed to save password: ' + err.message);
        }
      }

      async function testSycopeConnection() {
        var btn = document.getElementById('test-btn');
        btn.disabled = true;
        btn.textContent = 'Testing...';
        document.getElementById('test-result').style.display = 'none';

        try {
          var res = await fetch('/api/v1/admin/config/sycope', { credentials: 'include' });
          var cfg = await res.json();

          if (!cfg.sycope_host) { showTestResult(false, 'Sycope Host is not set.'); return; }
          if (!cfg.sycope_login) { showTestResult(false, 'Username is not set.'); return; }
          if (!cfg.sycope_pass_set) { showTestResult(false, 'Password is not set. Enter and save it above.'); return; }

          showTestResult(true,
            'Configuration complete. Host: ' + cfg.sycope_host +
            ', User: ' + cfg.sycope_login +
            '. Actual sync performed by trueid_sync.py connector.');
        } catch (err) {
          showTestResult(false, 'Test failed: ' + err.message);
        } finally {
          btn.disabled = false;
          btn.textContent = 'Test Connection';
        }
      }

      function showTestResult(ok, message) {
        var el = document.getElementById('test-result');
        el.style.display = 'block';
        el.style.background = ok ? 'var(--status-ok-soft)' : 'var(--status-error-soft)';
        el.style.border = '1px solid ' + (ok ? 'var(--status-ok)' : 'var(--status-error)');
        el.style.color = ok ? 'var(--status-ok)' : 'var(--status-error)';
        el.textContent = (ok ? 'OK: ' : 'Error: ') + message;
      }

      function renderSyncStatus(sync) {
        var el = document.getElementById('sync-status');
        if (!sync || !sync.status) {
          el.innerHTML = '<span class="muted">No sync has been performed yet. ' +
            'Configure the settings above and run the connector:<br>' +
            '<code style="color:var(--green-bright);">cd integrations/sycope && python3 trueid_sync.py</code></span>';
          return;
        }
        var when = sync.last_run_at ? new Date(sync.last_run_at).toLocaleString() : 'unknown';
        var ok = sync.status === 'ok';
        var color = ok ? 'var(--status-ok)' : 'var(--status-error)';
        var html = '<div style="display:flex;gap:16px;align-items:baseline;">' +
          '<span style="color:' + color + ';font-size:16px;">' + (ok ? '●' : '✗') + '</span>' +
          '<div>' +
          '<div>Last sync: <strong>' + when + '</strong></div>' +
          '<div>Status: <span style="color:' + color + ';">' + sync.status + '</span></div>';
        if (sync.records_synced !== undefined) {
          html += '<div>Records synced: ' + sync.records_synced + '</div>';
        }
        if (sync.message) {
          html += '<div style="color:var(--status-error);margin-top:4px;">Message: ' + sync.message + '</div>';
        }
        html += '</div></div>';
        el.innerHTML = html;
      }

(function () {
  window.TrueID = window.TrueID || {};
  if (typeof window.buildNotificationConfigPayload === 'function') window.TrueID.buildNotificationConfigPayload = window.buildNotificationConfigPayload;
  if (typeof window.deleteFirewallTarget === 'function') window.TrueID.deleteFirewallTarget = window.deleteFirewallTarget;
  if (typeof window.deleteNotificationChannel === 'function') window.TrueID.deleteNotificationChannel = window.deleteNotificationChannel;
  if (typeof window.deleteSiemTarget === 'function') window.TrueID.deleteSiemTarget = window.deleteSiemTarget;
  if (typeof window.editFirewallTarget === 'function') window.TrueID.editFirewallTarget = window.editFirewallTarget;
  if (typeof window.editSiemTarget === 'function') window.TrueID.editSiemTarget = window.editSiemTarget;
  if (typeof window.firewallTypeBadge === 'function') window.TrueID.firewallTypeBadge = window.firewallTypeBadge;
  if (typeof window.forceFirewallPush === 'function') window.TrueID.forceFirewallPush = window.forceFirewallPush;
  if (typeof window.forceLdapSync === 'function') window.TrueID.forceLdapSync = window.forceLdapSync;
  if (typeof window.hideFirewallForm === 'function') window.TrueID.hideFirewallForm = window.hideFirewallForm;
  if (typeof window.hideNotificationForm === 'function') window.TrueID.hideNotificationForm = window.hideNotificationForm;
  if (typeof window.hideSiemForm === 'function') window.TrueID.hideSiemForm = window.hideSiemForm;
  if (typeof window.loadChannelDeliveries === 'function') window.TrueID.loadChannelDeliveries = window.loadChannelDeliveries;
  if (typeof window.loadFirewallHistory === 'function') window.TrueID.loadFirewallHistory = window.loadFirewallHistory;
  if (typeof window.loadFirewallStats === 'function') window.TrueID.loadFirewallStats = window.loadFirewallStats;
  if (typeof window.loadFirewallTab === 'function') window.TrueID.loadFirewallTab = window.loadFirewallTab;
  if (typeof window.loadFirewallTargets === 'function') window.TrueID.loadFirewallTargets = window.loadFirewallTargets;
  if (typeof window.loadLdapConfig === 'function') window.TrueID.loadLdapConfig = window.loadLdapConfig;
  if (typeof window.loadLdapGroupMembers === 'function') window.TrueID.loadLdapGroupMembers = window.loadLdapGroupMembers;
  if (typeof window.loadLdapGroups === 'function') window.TrueID.loadLdapGroups = window.loadLdapGroups;
  if (typeof window.loadLdapTab === 'function') window.TrueID.loadLdapTab = window.loadLdapTab;
  if (typeof window.loadNotificationsTab === 'function') window.TrueID.loadNotificationsTab = window.loadNotificationsTab;
  if (typeof window.loadSiemStats === 'function') window.TrueID.loadSiemStats = window.loadSiemStats;
  if (typeof window.loadSiemTab === 'function') window.TrueID.loadSiemTab = window.loadSiemTab;
  if (typeof window.loadSiemTargets === 'function') window.TrueID.loadSiemTargets = window.loadSiemTargets;
  if (typeof window.loadSycopeConfig === 'function') window.TrueID.loadSycopeConfig = window.loadSycopeConfig;
  if (typeof window.lookupLdapUserGroups === 'function') window.TrueID.lookupLdapUserGroups = window.lookupLdapUserGroups;
  if (typeof window.renderNotificationConfigForm === 'function') window.TrueID.renderNotificationConfigForm = window.renderNotificationConfigForm;
  if (typeof window.renderSyncStatus === 'function') window.TrueID.renderSyncStatus = window.renderSyncStatus;
  if (typeof window.saveFirewallTarget === 'function') window.TrueID.saveFirewallTarget = window.saveFirewallTarget;
  if (typeof window.saveLdapField === 'function') window.TrueID.saveLdapField = window.saveLdapField;
  if (typeof window.saveLdapPassword === 'function') window.TrueID.saveLdapPassword = window.saveLdapPassword;
  if (typeof window.saveNotificationChannel === 'function') window.TrueID.saveNotificationChannel = window.saveNotificationChannel;
  if (typeof window.saveSiemTarget === 'function') window.TrueID.saveSiemTarget = window.saveSiemTarget;
  if (typeof window.saveSycopeField === 'function') window.TrueID.saveSycopeField = window.saveSycopeField;
  if (typeof window.saveSycopePassword === 'function') window.TrueID.saveSycopePassword = window.saveSycopePassword;
  if (typeof window.showFirewallForm === 'function') window.TrueID.showFirewallForm = window.showFirewallForm;
  if (typeof window.showNotificationForm === 'function') window.TrueID.showNotificationForm = window.showNotificationForm;
  if (typeof window.showSiemForm === 'function') window.TrueID.showSiemForm = window.showSiemForm;
  if (typeof window.showTestResult === 'function') window.TrueID.showTestResult = window.showTestResult;
  if (typeof window.siemFormatBadge === 'function') window.TrueID.siemFormatBadge = window.siemFormatBadge;
  if (typeof window.siemTransportBadge === 'function') window.TrueID.siemTransportBadge = window.siemTransportBadge;
  if (typeof window.testFirewallTarget === 'function') window.TrueID.testFirewallTarget = window.testFirewallTarget;
  if (typeof window.testNotificationChannel === 'function') window.TrueID.testNotificationChannel = window.testNotificationChannel;
  if (typeof window.testSycopeConnection === 'function') window.TrueID.testSycopeConnection = window.testSycopeConnection;
  if (typeof window.toggleFirewallHistory === 'function') window.TrueID.toggleFirewallHistory = window.toggleFirewallHistory;
  if (typeof window.toggleFirewallUsername === 'function') window.TrueID.toggleFirewallUsername = window.toggleFirewallUsername;
})();
