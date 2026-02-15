/* Network module (subnets, switches, fingerprints, DNS). */

async function loadSubnetsTab() {
        await loadSubnetsStats();
        await loadSubnets(1);
        await loadDiscoveredSubnets();
      }

      /**
       * Sorts rows using per-tab sort state.
       * Parameters: tabName - logical tab key, rows - list of objects.
       * Returns: sorted rows.
       */
      function sortNetworkRows(tabName, rows) {
        var state = window.sortState && window.sortState[tabName];
        if (!state || !state.column) return rows;
        var dir = state.direction === 'desc' ? -1 : 1;
        return rows.slice().sort(function (a, b) {
          var av = a[state.column];
          var bv = b[state.column];
          if (state.column === 'mappings') {
            av = subnetCounts[a.id] != null ? subnetCounts[a.id] : 0;
            bv = subnetCounts[b.id] != null ? subnetCounts[b.id] : 0;
          }
          if (av == null && bv == null) return 0;
          if (av == null) return -1 * dir;
          if (bv == null) return 1 * dir;
          if (typeof av === 'number' && typeof bv === 'number') return (av - bv) * dir;
          return String(av).localeCompare(String(bv)) * dir;
        });
      }

      async function loadSubnetsStats() {
        try {
          var res = await fetch('/api/v2/subnets/stats', { credentials: 'include' });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          var s = await res.json();
          subnetCounts = {};
          (s.per_subnet || []).forEach(function (r) {
            subnetCounts[r.id] = r.total_mappings || 0;
          });
          var totalMappings = (s.total_tagged_mappings || 0) + (s.untagged_mappings || 0);
          var cov = totalMappings > 0 ? Math.round((s.total_tagged_mappings || 0) * 100 / totalMappings) : 0;
          document.getElementById('subnets-stats').innerHTML =
            '<span>Total subnets: <strong>' + (s.total_subnets || 0) + '</strong></span>' +
            '<span>Total mappings tagged: <strong>' + (s.total_tagged_mappings || 0) + '</strong></span>' +
            '<span>Coverage: <strong>' + cov + '%</strong></span>';
        } catch (e) {
          document.getElementById('subnets-stats').innerHTML = '<span class="muted">No stats available.</span>';
        }
      }

      async function loadSubnets(page) {
        subnetCurrentPage = page || 1;
        try {
          var res = await fetch('/api/v2/subnets', { credentials: 'include' });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          var all = await res.json();
          subnets = Array.isArray(all) ? all : [];
          var start = (subnetCurrentPage - 1) * subnetPageSize;
          var sorted = sortNetworkRows('subnets', subnets);
          var rows = sorted.slice(start, start + subnetPageSize);
          var body = document.getElementById('subnets-body');
          if (!rows.length) {
            body.innerHTML = '<tr><td colspan="7" class="muted">No subnets configured.</td></tr>';
            renderPager('subnets-paging', subnetCurrentPage, subnetPageSize, sorted.length, 'loadSubnets');
            applySortHeaders('subnets-table', 'subnets', null, loadSubnets);
            return;
          }
          body.innerHTML = rows.map(function (s) {
            var actions =
              '<button class="btn btn-sm role-operator" onclick="event.stopPropagation();editSubnet(' + s.id + ')">Edit</button> ' +
              '<button class="btn btn-sm role-operator" onclick="event.stopPropagation();deleteSubnet(' + s.id + ')">Delete</button>';
            return '<tr class="expand-row" onclick="toggleSubnetMappings(' + s.id + ')">' +
              '<td>' + escapeHtml(s.name || '-') + '</td>' +
              '<td>' + escapeHtml(s.cidr || '-') + '</td>' +
              '<td>' + escapeHtml(s.vlan_id != null ? s.vlan_id : '-') + '</td>' +
              '<td>' + escapeHtml(s.location || '-') + '</td>' +
              '<td>' + escapeHtml(s.gateway || '-') + '</td>' +
              '<td><a class="ip-link" href="#" onclick="event.preventDefault();event.stopPropagation();toggleSubnetMappings(' + s.id + ')">' + escapeHtml(subnetCounts[s.id] != null ? subnetCounts[s.id] : 0) + ' mappings</a></td>' +
              '<td>' + actions + '</td>' +
              '</tr>' +
              '<tr id="subnet-map-row-' + s.id + '" style="display:' + (subnetMappingOpen[s.id] ? '' : 'none') + ';"><td colspan="7"><div id="subnet-map-' + s.id + '" class="muted">Loading mappings...</div></td></tr>';
          }).join('');
          renderPager('subnets-paging', subnetCurrentPage, subnetPageSize, sorted.length, 'loadSubnets');
          applySortHeaders('subnets-table', 'subnets', null, loadSubnets);
          applyRoleVisibility(currentUser.role);
        } catch (e) {
          document.getElementById('subnets-body').innerHTML =
            '<tr><td colspan="7" style="color:var(--status-error);">Failed: ' + escapeHtml(e.message) + '</td></tr>';
        }
      }

      function showSubnetForm(item) {
        document.getElementById('subnet-form-wrap').style.display = '';
        document.getElementById('subnet-form-wrap').setAttribute('data-edit-id', item && item.id ? String(item.id) : '');
        document.getElementById('subnet-name').value = item ? (item.name || '') : '';
        document.getElementById('subnet-cidr').value = item ? (item.cidr || '') : '';
        document.getElementById('subnet-vlan').value = item && item.vlan_id != null ? item.vlan_id : '';
        document.getElementById('subnet-location').value = item ? (item.location || '') : '';
        document.getElementById('subnet-description').value = item ? (item.description || '') : '';
        document.getElementById('subnet-gateway').value = item ? (item.gateway || '') : '';
      }

      function hideSubnetForm() {
        document.getElementById('subnet-form-wrap').style.display = 'none';
        document.getElementById('subnet-form-wrap').setAttribute('data-edit-id', '');
      }

      function editSubnet(id) {
        var item = subnets.find(function (s) { return s.id === id; });
        if (item) showSubnetForm(item);
      }

      async function saveSubnet() {
        var editId = document.getElementById('subnet-form-wrap').getAttribute('data-edit-id');
        var payload = {
          name: document.getElementById('subnet-name').value.trim(),
          cidr: document.getElementById('subnet-cidr').value.trim(),
          vlan_id: document.getElementById('subnet-vlan').value ? parseInt(document.getElementById('subnet-vlan').value, 10) : null,
          location: document.getElementById('subnet-location').value.trim() || null,
          description: document.getElementById('subnet-description').value.trim() || null,
          gateway: document.getElementById('subnet-gateway').value.trim() || null
        };
        var method = editId ? 'PUT' : 'POST';
        var url = editId ? '/api/v2/subnets/' + encodeURIComponent(editId) : '/api/v2/subnets';
        try {
          var res = await fetch(url, {
            method: method,
            headers: mutHeaders(),
            credentials: 'include',
            body: JSON.stringify(payload)
          });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          hideSubnetForm();
          loadSubnetsStats();
          loadSubnets(subnetCurrentPage);
        } catch (e) {
          alert('Save failed: ' + e.message);
        }
      }

      async function deleteSubnet(id) {
        if (!confirm('Delete subnet #' + id + '?')) return;
        try {
          var res = await fetch('/api/v2/subnets/' + encodeURIComponent(id), {
            method: 'DELETE',
            headers: mutHeaders(),
            credentials: 'include'
          });
          if (!res.ok && res.status !== 204) throw new Error('HTTP ' + res.status);
          loadSubnetsStats();
          loadSubnets(subnetCurrentPage);
        } catch (e) {
          alert('Delete failed: ' + e.message);
        }
      }

      function toggleSubnetMappings(id) {
        subnetMappingOpen[id] = !subnetMappingOpen[id];
        var row = document.getElementById('subnet-map-row-' + id);
        if (!row) return;
        row.style.display = subnetMappingOpen[id] ? '' : 'none';
        if (subnetMappingOpen[id]) loadSubnetMappings(id, 1);
      }

      async function loadSubnetMappings(id, page) {
        try {
          var res = await fetch('/api/v2/subnets/' + encodeURIComponent(id) + '/mappings?page=' + (page || 1) + '&per_page=50', { credentials: 'include' });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          var data = await res.json();
          var rows = data.data || [];
          var box = document.getElementById('subnet-map-' + id);
          if (!rows.length) {
            box.innerHTML = '<span class="muted">No mappings for this subnet.</span>';
            return;
          }
          box.innerHTML = '<table><thead><tr><th>IP</th><th>User</th><th>MAC</th><th>Source</th><th>Last Seen</th></tr></thead><tbody>' +
            rows.map(function (m) {
              var user = Array.isArray(m.current_users) && m.current_users.length ? m.current_users.join(', ') : (m.user || '-');
              var primary = Array.isArray(m.current_users) && m.current_users.length ? m.current_users[0] : (m.user || '');
              return '<tr>' +
                '<td><a href="#" class="ip-link" onclick="openTimeline(\'ip\', \'' + escJs(m.ip || '') + '\');return false;">' + escapeHtml(m.ip || '-') + '</a></td>' +
                '<td><a href="#" class="ip-link" onclick="openTimeline(\'user\', \'' + escJs(primary) + '\');return false;">' + escapeHtml(user) + '</a></td>' +
                '<td>' + escapeHtml(m.mac || '-') + '</td>' +
                '<td>' + escapeHtml(m.source || '-') + '</td>' +
                '<td>' + escapeHtml(timeAgo(m.last_seen)) + '</td>' +
                '</tr>';
            }).join('') + '</tbody></table>';
        } catch (e) {
          document.getElementById('subnet-map-' + id).innerHTML = '<span style="color:var(--status-error);">Failed: ' + escapeHtml(e.message) + '</span>';
        }
      }

      async function loadDiscoveredSubnets() {
        try {
          var res = await fetch('/api/v2/subnets/discovered', { credentials: 'include' });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          var body = await res.json();
          var rows = body.data || [];
          var el = document.getElementById('discovered-subnets-body');
          if (!rows.length) {
            el.innerHTML = '<tr><td colspan="6" class="muted">No discovered subnets.</td></tr>';
            return;
          }
          el.innerHTML = rows.map(function (r) {
            var status = r.promoted ? '<span class="badge badge-info">Promoted</span>' : '<span class="badge badge-warning">New</span>';
            var actions = '';
            if (!r.promoted) actions += '<button class="btn btn-sm role-operator" onclick="promoteDiscoveredSubnet(' + r.id + ', \'' + escJs(r.cidr) + '\')">Promote</button> ';
            actions += '<button class="btn btn-sm role-admin" onclick="dismissDiscoveredSubnet(' + r.id + ')">Dismiss</button>';
            return '<tr>' +
              '<td>' + escapeHtml(r.cidr || '-') + '</td>' +
              '<td>' + escapeHtml(r.ip_count || 0) + '</td>' +
              '<td>' + escapeHtml(timeAgo(r.first_seen)) + '</td>' +
              '<td>' + escapeHtml(timeAgo(r.last_seen)) + '</td>' +
              '<td>' + status + '</td>' +
              '<td>' + actions + '</td>' +
              '</tr>';
          }).join('');
          applyRoleVisibility(currentUser.role);
        } catch (e) {
          document.getElementById('discovered-subnets-body').innerHTML =
            '<tr><td colspan="6" style="color:var(--status-error);">Failed: ' + escapeHtml(e.message) + '</td></tr>';
        }
      }

      async function promoteDiscoveredSubnet(id, cidr) {
        var name = prompt('Name for discovered subnet ' + cidr + ':', 'Auto-discovered ' + cidr);
        if (!name) return;
        try {
          var res = await fetch('/api/v2/subnets/promote', {
            method: 'POST',
            headers: mutHeaders(),
            credentials: 'include',
            body: JSON.stringify({ discovered_id: id, name: name, vlan_id: null })
          });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          await loadSubnetsTab();
        } catch (e) {
          alert('Promote failed: ' + e.message);
        }
      }

      async function dismissDiscoveredSubnet(id) {
        if (!confirm('Dismiss discovered subnet #' + id + '?')) return;
        try {
          var res = await fetch('/api/v2/subnets/discovered/' + encodeURIComponent(id), {
            method: 'DELETE',
            headers: mutHeaders(),
            credentials: 'include'
          });
          if (!res.ok && res.status !== 204) throw new Error('HTTP ' + res.status);
          await loadDiscoveredSubnets();
        } catch (e) {
          alert('Dismiss failed: ' + e.message);
        }
      }

      async function loadSwitchesTab() {
        await loadSwitchesStats();
        await loadSwitches(1);
      }

      async function loadSwitchesStats() {
        try {
          var res = await fetch('/api/v2/switches/stats', { credentials: 'include' });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          var s = await res.json();
          document.getElementById('switches-stats').innerHTML =
            '<span>Total switches: <strong>' + (s.total_switches || 0) + '</strong></span>' +
            '<span>Enabled: <strong>' + (s.enabled_switches || 0) + '</strong></span>' +
            '<span>Total ports mapped: <strong>' + (s.total_mac_entries || 0) + '</strong></span>' +
            '<span>Last poll: <strong>' + escapeHtml(timeAgo(s.last_poll_time)) + '</strong></span>';
        } catch (e) {
          document.getElementById('switches-stats').innerHTML = '<span class="muted">No stats available.</span>';
        }
      }

      async function loadSwitches(page) {
        switchesCurrentPage = page || 1;
        try {
          var res = await fetch('/api/v2/switches', { credentials: 'include' });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          var all = await res.json();
          switches = Array.isArray(all) ? all : [];
          var start = (switchesCurrentPage - 1) * switchesPageSize;
          var sorted = sortNetworkRows('switches', switches);
          var rows = sorted.slice(start, start + switchesPageSize);
          var body = document.getElementById('switches-body');
          if (!rows.length) {
            body.innerHTML = '<tr><td colspan="9" class="muted">No switches configured.</td></tr>';
            renderPager('switches-paging', switchesCurrentPage, switchesPageSize, sorted.length, 'loadSwitches');
            applySortHeaders('switches-table', 'switches', null, loadSwitches);
            return;
          }
          body.innerHTML = rows.map(function (s) {
            var actions =
              '<button class="btn btn-sm role-operator" onclick="event.stopPropagation();pollSwitch(' + s.id + ')">Poll Now</button> ' +
              '<button class="btn btn-sm role-operator" onclick="event.stopPropagation();editSwitch(' + s.id + ')">Edit</button> ' +
              '<button class="btn btn-sm role-operator" onclick="event.stopPropagation();deleteSwitch(' + s.id + ')">Delete</button>';
            return '<tr class="expand-row" onclick="toggleSwitchPorts(' + s.id + ')">' +
              '<td>' + escapeHtml(s.name || '-') + '<div id="sw-msg-' + s.id + '" class="muted" style="font-size:11px;"></div></td>' +
              '<td>' + escapeHtml(s.ip || '-') + '</td>' +
              '<td>' + escapeHtml(s.snmp_version || '-') + '</td>' +
              '<td>' + escapeHtml((s.poll_interval_secs || '-') + 's') + '</td>' +
              '<td><span class="dot ' + (s.enabled ? 'online' : 'offline') + '"></span></td>' +
              '<td>' + escapeHtml(timeAgo(s.last_polled_at)) + '</td>' +
              '<td>' + escapeHtml(s.last_poll_status || '-') + '</td>' +
              '<td>' + escapeHtml(s.mac_count != null ? s.mac_count : 0) + '</td>' +
              '<td>' + actions + '</td>' +
              '</tr>' +
              '<tr id="sw-ports-row-' + s.id + '" style="display:' + (switchPortOpen[s.id] ? '' : 'none') + ';"><td colspan="9"><div id="sw-ports-' + s.id + '" class="muted">Loading ports...</div></td></tr>';
          }).join('');
          renderPager('switches-paging', switchesCurrentPage, switchesPageSize, sorted.length, 'loadSwitches');
          applySortHeaders('switches-table', 'switches', null, loadSwitches);
          applyRoleVisibility(currentUser.role);
        } catch (e) {
          document.getElementById('switches-body').innerHTML =
            '<tr><td colspan="9" style="color:var(--status-error);">Failed: ' + escapeHtml(e.message) + '</td></tr>';
        }
      }

      async function loadSubnetSelect(targetId, selectedId) {
        try {
          var res = await fetch('/api/v2/subnets', { credentials: 'include' });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          var rows = await res.json();
          var sel = document.getElementById(targetId);
          sel.innerHTML = '<option value="">No subnet</option>' + (rows || []).map(function (s) {
            var selected = selectedId != null && Number(selectedId) === Number(s.id) ? ' selected' : '';
            return '<option value="' + s.id + '"' + selected + '>' + escapeHtml(s.name + ' (' + s.cidr + ')') + '</option>';
          }).join('');
        } catch (e) {}
      }

      function showSwitchForm(item) {
        switchEditingId = item && item.id ? item.id : null;
        document.getElementById('switch-form-wrap').style.display = '';
        document.getElementById('switch-name').value = item ? (item.name || '') : '';
        document.getElementById('switch-ip').value = item ? (item.ip || '') : '';
        document.getElementById('switch-community').value = '';
        document.getElementById('switch-version').value = item ? (item.snmp_version || 'v2c') : 'v2c';
        document.getElementById('switch-port').value = item ? (item.port || 161) : 161;
        document.getElementById('switch-interval').value = item ? (item.poll_interval_secs || 300) : 300;
        document.getElementById('switch-location').value = item ? (item.location || '') : '';
        document.getElementById('switch-enabled').checked = item ? !!item.enabled : true;
        loadSubnetSelect('switch-subnet', item ? item.subnet_id : null);
      }

      function hideSwitchForm() {
        switchEditingId = null;
        document.getElementById('switch-form-wrap').style.display = 'none';
      }

      function editSwitch(id) {
        var item = switches.find(function (s) { return s.id === id; });
        if (item) showSwitchForm(item);
      }

      async function saveSwitch() {
        var payload = {
          name: document.getElementById('switch-name').value.trim(),
          ip: document.getElementById('switch-ip').value.trim(),
          community: document.getElementById('switch-community').value.trim(),
          snmp_version: document.getElementById('switch-version').value,
          port: parseInt(document.getElementById('switch-port').value || '161', 10),
          poll_interval_secs: parseInt(document.getElementById('switch-interval').value || '300', 10),
          subnet_id: document.getElementById('switch-subnet').value ? parseInt(document.getElementById('switch-subnet').value, 10) : null,
          location: document.getElementById('switch-location').value.trim() || null,
          enabled: document.getElementById('switch-enabled').checked
        };
        if (switchEditingId && !payload.community) delete payload.community;
        var method = switchEditingId ? 'PUT' : 'POST';
        var url = switchEditingId ? '/api/v2/switches/' + encodeURIComponent(switchEditingId) : '/api/v2/switches';
        try {
          var res = await fetch(url, {
            method: method,
            headers: mutHeaders(),
            credentials: 'include',
            body: JSON.stringify(payload)
          });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          hideSwitchForm();
          loadSwitchesStats();
          loadSwitches(switchesCurrentPage);
        } catch (e) {
          alert('Save failed: ' + e.message);
        }
      }

      async function deleteSwitch(id) {
        if (!confirm('Delete switch #' + id + '?')) return;
        try {
          var res = await fetch('/api/v2/switches/' + encodeURIComponent(id), {
            method: 'DELETE',
            headers: mutHeaders(),
            credentials: 'include'
          });
          if (!res.ok && res.status !== 204) throw new Error('HTTP ' + res.status);
          loadSwitchesStats();
          loadSwitches(switchesCurrentPage);
        } catch (e) {
          alert('Delete failed: ' + e.message);
        }
      }

      async function pollSwitch(id) {
        try {
          var res = await fetch('/api/v2/switches/' + encodeURIComponent(id) + '/poll', {
            method: 'POST',
            headers: mutHeaders(),
            credentials: 'include'
          });
          var data = await res.json();
          var el = document.getElementById('sw-msg-' + id);
          if (res.ok) {
            el.textContent = data.message || 'Poll queued';
            el.style.color = 'var(--status-ok)';
          } else {
            el.textContent = data.message || ('HTTP ' + res.status);
            el.style.color = 'var(--status-error)';
          }
        } catch (e) {
          var el2 = document.getElementById('sw-msg-' + id);
          el2.textContent = 'Poll failed: ' + e.message;
          el2.style.color = 'var(--status-error)';
        }
      }

      function toggleSwitchPorts(id) {
        switchPortOpen[id] = !switchPortOpen[id];
        var row = document.getElementById('sw-ports-row-' + id);
        if (!row) return;
        row.style.display = switchPortOpen[id] ? '' : 'none';
        if (switchPortOpen[id]) loadSwitchPorts(id, 1);
      }

      async function loadSwitchPorts(id, page) {
        try {
          var res = await fetch('/api/v2/switch-ports?switch_id=' + encodeURIComponent(id) + '&page=' + (page || 1) + '&limit=50', { credentials: 'include' });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          var data = await res.json();
          var rows = data.data || [];
          var box = document.getElementById('sw-ports-' + id);
          if (!rows.length) {
            box.innerHTML = '<span class="muted">No mapped ports.</span>';
            return;
          }
          box.innerHTML = '<table><thead><tr><th>Port Name</th><th>VLAN</th><th>MAC</th><th>IP</th><th>Last Seen</th></tr></thead><tbody>' +
            rows.map(function (r) {
              return '<tr>' +
                '<td>' + escapeHtml(r.port_name || ('port-' + r.port_index)) + '</td>' +
                '<td>' + escapeHtml(r.vlan_id != null ? r.vlan_id : '-') + '</td>' +
                '<td>' + escapeHtml(r.mac || '-') + '</td>' +
                '<td>-</td>' +
                '<td>' + escapeHtml(timeAgo(r.last_seen)) + '</td>' +
                '</tr>';
            }).join('') + '</tbody></table>';
        } catch (e) {
          document.getElementById('sw-ports-' + id).innerHTML = '<span style="color:var(--status-error);">Failed: ' + escapeHtml(e.message) + '</span>';
        }
      }

      async function loadFingerprintsTab() {
        await loadFingerprintStats();
        await loadFingerprintList(1);
        await loadFingerprintObservations(1);
      }

      async function loadFingerprintStats() {
        try {
          var res = await fetch('/api/v2/fingerprints/stats', { credentials: 'include' });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          var s = await res.json();
          var unique = Array.isArray(s.device_type_breakdown) ? s.device_type_breakdown.length : 0;
          document.getElementById('fp-stats').innerHTML =
            '<span>Total fingerprints: <strong>' + (s.total_fingerprints || 0) + '</strong></span>' +
            '<span>Total observations: <strong>' + (s.total_observations || 0) + '</strong></span>' +
            '<span>Unique device types: <strong>' + unique + '</strong></span>';
        } catch (e) {
          document.getElementById('fp-stats').innerHTML = '<span class="muted">No stats available.</span>';
        }
      }

      function showFingerprintForm() {
        document.getElementById('fp-form-wrap').style.display = '';
      }

      function hideFingerprintForm() {
        document.getElementById('fp-form-wrap').style.display = 'none';
      }

      async function saveFingerprint() {
        var payload = {
          fingerprint: document.getElementById('fp-fingerprint').value.trim(),
          device_type: document.getElementById('fp-device-type').value.trim(),
          os_family: document.getElementById('fp-os-family').value.trim() || null,
          description: document.getElementById('fp-description').value.trim() || null
        };
        try {
          var res = await fetch('/api/v2/fingerprints', {
            method: 'POST',
            headers: mutHeaders(),
            credentials: 'include',
            body: JSON.stringify(payload)
          });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          hideFingerprintForm();
          loadFingerprintStats();
          loadFingerprintList(fpCurrentPage);
        } catch (e) {
          alert('Save failed: ' + e.message);
        }
      }

      async function loadFingerprintList(page) {
        fpCurrentPage = page || 1;
        try {
          var res = await fetch('/api/v2/fingerprints', { credentials: 'include' });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          var all = await res.json();
          fingerprints = Array.isArray(all) ? all : [];
          var start = (fpCurrentPage - 1) * fpPageSize;
          var sorted = sortNetworkRows('fingerprints', fingerprints);
          var rows = sorted.slice(start, start + fpPageSize);
          var obsMap = {};
          try {
            var obsRes = await fetch('/api/v2/fingerprints/observations?page=1&limit=200', { credentials: 'include' });
            if (obsRes.ok) {
              var obsData = await obsRes.json();
              (obsData.data || []).forEach(function (o) {
                var key = o.fingerprint || '';
                obsMap[key] = (obsMap[key] || 0) + 1;
              });
            }
          } catch (_) {}
          var body = document.getElementById('fp-body');
          if (!rows.length) {
            body.innerHTML = '<tr><td colspan="6" class="muted">No fingerprints.</td></tr>';
            renderPager('fp-paging', fpCurrentPage, fpPageSize, sorted.length, 'loadFingerprintList');
            applySortHeaders('fingerprints-table', 'fingerprints', null, loadFingerprintList);
            return;
          }
          body.innerHTML = rows.map(function (f) {
            var actions = '<button class="btn btn-sm role-admin" onclick="deleteFingerprint(' + f.id + ')">Delete</button>';
            return '<tr>' +
              '<td title="' + escapeHtml(f.fingerprint || '-') + '">' + trimFingerprint(f.fingerprint) + '</td>' +
              '<td>' + escapeHtml(f.device_type || '-') + '</td>' +
              '<td>' + escapeHtml(f.os_family || '-') + '</td>' +
              '<td>' + escapeHtml(f.description || '-') + '</td>' +
              '<td>' + escapeHtml(obsMap[f.fingerprint || ''] || 0) + '</td>' +
              '<td>' + actions + '</td>' +
              '</tr>';
          }).join('');
          applySortHeaders('fingerprints-table', 'fingerprints', null, loadFingerprintList);
          renderPager('fp-paging', fpCurrentPage, fpPageSize, sorted.length, 'loadFingerprintList');
          applyRoleVisibility(currentUser.role);
        } catch (e) {
          document.getElementById('fp-body').innerHTML =
            '<tr><td colspan="6" style="color:var(--status-error);">Failed: ' + escapeHtml(e.message) + '</td></tr>';
        }
      }

      async function deleteFingerprint(id) {
        if (!confirm('Delete fingerprint #' + id + '?')) return;
        try {
          var res = await fetch('/api/v2/fingerprints/' + encodeURIComponent(id), {
            method: 'DELETE',
            headers: mutHeaders(),
            credentials: 'include'
          });
          if (!res.ok && res.status !== 204) throw new Error('HTTP ' + res.status);
          loadFingerprintList(fpCurrentPage);
          loadFingerprintStats();
        } catch (e) {
          alert('Delete failed: ' + e.message);
        }
      }

      async function runFingerprintBackfill() {
        try {
          var res = await fetch('/api/v2/fingerprints/backfill', {
            method: 'POST',
            headers: mutHeaders(),
            credentials: 'include',
            body: JSON.stringify({})
          });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          alert('Backfill initiated. Existing mappings will be re-matched against fingerprint database.');
        } catch (e) {
          alert('Backfill failed: ' + e.message);
        }
      }

      async function loadFingerprintObservations(page) {
        fpObsCurrentPage = page || 1;
        try {
          var res = await fetch('/api/v2/fingerprints/observations?page=' + fpObsCurrentPage + '&limit=50', { credentials: 'include' });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          var data = await res.json();
          var rows = sortNetworkRows('fingerprintObservations', data.data || []);
          var body = document.getElementById('fp-obs-body');
          if (!rows.length) {
            body.innerHTML = '<tr><td colspan="7" class="muted">No observations.</td></tr>';
            renderPager('fp-obs-paging', fpObsCurrentPage, 50, data.total || 0, 'loadFingerprintObservations');
            return;
          }
          body.innerHTML = rows.map(function (o) {
            return '<tr>' +
              '<td>' + escapeHtml(o.mac || '-') + '</td>' +
              '<td>' + escapeHtml(o.ip || '-') + '</td>' +
              '<td title="' + escapeHtml(o.fingerprint || '-') + '">' + trimFingerprint(o.fingerprint) + '</td>' +
              '<td>' + escapeHtml(o.device_type || 'unknown') + '</td>' +
              '<td>' + escapeHtml(o.hostname || '-') + '</td>' +
              '<td>' + escapeHtml(new Date(o.observed_at).toLocaleString()) + '</td>' +
              '<td>' + escapeHtml(timeAgo(o.observed_at)) + '</td>' +
              '</tr>';
          }).join('');
          applySortHeaders('fp-obs-table', 'fingerprintObservations', null, loadFingerprintObservations);
          renderPager('fp-obs-paging', fpObsCurrentPage, 50, data.total || 0, 'loadFingerprintObservations');
        } catch (e) {
          document.getElementById('fp-obs-body').innerHTML =
            '<tr><td colspan="7" style="color:var(--status-error);">Failed: ' + escapeHtml(e.message) + '</td></tr>';
        }
      }

      async function loadDnsTab() {
        await loadDnsStats();
        await loadDnsList(1);
      }

      async function loadDnsStats() {
        try {
          var res = await fetch('/api/v2/dns/stats', { credentials: 'include' });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          var s = await res.json();
          document.getElementById('dns-stats').innerHTML =
            '<span>Cached entries: <strong>' + (s.total_cached || 0) + '</strong></span>' +
            '<span>Successful lookups: <strong>' + (s.resolved_ok || 0) + '</strong></span>' +
            '<span>Failed lookups: <strong>' + (s.unresolved || 0) + '</strong></span>';
        } catch (e) {
          document.getElementById('dns-stats').innerHTML = '<span class="muted">No stats available.</span>';
        }
      }

      async function loadDnsList(page) {
        dnsCurrentPage = page || 1;
        try {
          var sortParams = getSortParams('dns');
          var url = '/api/v2/dns?page=' + dnsCurrentPage + '&limit=50';
          if (sortParams) url += sortParams;
          var res = await fetch(url, { credentials: 'include' });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          var data = await res.json();
          var rows = sortNetworkRows('dns', data.data || []);
          var body = document.getElementById('dns-body');
          if (!rows.length) {
            body.innerHTML = '<tr><td colspan="4" class="muted">No DNS cache entries.</td></tr>';
            renderPager('dns-paging', dnsCurrentPage, 50, data.total || 0, 'loadDnsList');
            return;
          }
          body.innerHTML = rows.map(function (d) {
            return '<tr>' +
              '<td><a href="#" class="ip-link" onclick="openTimeline(\'ip\', \'' + escJs(d.ip || '') + '\');return false;">' + escapeHtml(d.ip || '-') + '</a></td>' +
              '<td>' + escapeHtml(d.hostname || '-') + '</td>' +
              '<td>' + escapeHtml(d.resolved_at ? new Date(d.resolved_at).toLocaleString() : '-') + '</td>' +
              '<td>' + escapeHtml(timeAgo(d.expires_at)) + '</td>' +
              '</tr>';
          }).join('');
          applySortHeaders('dns-table', 'dns', null, loadDnsList);
          renderPager('dns-paging', dnsCurrentPage, 50, data.total || 0, 'loadDnsList');
        } catch (e) {
          document.getElementById('dns-body').innerHTML =
            '<tr><td colspan="4" style="color:var(--status-error);">Failed: ' + escapeHtml(e.message) + '</td></tr>';
        }
      }

      async function dnsLookupIp() {
        var ip = document.getElementById('dns-lookup-ip').value.trim();
        if (!ip) return;
        var out = document.getElementById('dns-lookup-result');
        try {
          var res = await fetch('/api/v2/dns/' + encodeURIComponent(ip), { credentials: 'include' });
          if (res.status === 404) {
            out.textContent = 'not cached';
            out.style.color = 'var(--text-secondary)';
            return;
          }
          if (!res.ok) throw new Error('HTTP ' + res.status);
          var data = await res.json();
          out.textContent = 'hostname: ' + (data.hostname || 'not cached');
          out.style.color = 'var(--status-ok)';
        } catch (e) {
          out.textContent = 'lookup failed: ' + e.message;
          out.style.color = 'var(--status-error)';
        }
      }

      async function flushDnsCache() {
        if (!confirm('Flush DNS cache?')) return;
        try {
          var res = await fetch('/api/v2/dns/flush', {
            method: 'POST',
            headers: mutHeaders(),
            credentials: 'include',
            body: JSON.stringify({})
          });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          alert('DNS cache flushed.');
          loadDnsTab();
        } catch (e) {
          alert('Flush failed: ' + e.message);
        }
      }

(function () {
  window.TrueID = window.TrueID || {};
  if (typeof window.deleteFingerprint === 'function') window.TrueID.deleteFingerprint = window.deleteFingerprint;
  if (typeof window.deleteSubnet === 'function') window.TrueID.deleteSubnet = window.deleteSubnet;
  if (typeof window.deleteSwitch === 'function') window.TrueID.deleteSwitch = window.deleteSwitch;
  if (typeof window.dismissDiscoveredSubnet === 'function') window.TrueID.dismissDiscoveredSubnet = window.dismissDiscoveredSubnet;
  if (typeof window.dnsLookupIp === 'function') window.TrueID.dnsLookupIp = window.dnsLookupIp;
  if (typeof window.editSubnet === 'function') window.TrueID.editSubnet = window.editSubnet;
  if (typeof window.editSwitch === 'function') window.TrueID.editSwitch = window.editSwitch;
  if (typeof window.flushDnsCache === 'function') window.TrueID.flushDnsCache = window.flushDnsCache;
  if (typeof window.hideFingerprintForm === 'function') window.TrueID.hideFingerprintForm = window.hideFingerprintForm;
  if (typeof window.hideSubnetForm === 'function') window.TrueID.hideSubnetForm = window.hideSubnetForm;
  if (typeof window.hideSwitchForm === 'function') window.TrueID.hideSwitchForm = window.hideSwitchForm;
  if (typeof window.loadDiscoveredSubnets === 'function') window.TrueID.loadDiscoveredSubnets = window.loadDiscoveredSubnets;
  if (typeof window.loadDnsList === 'function') window.TrueID.loadDnsList = window.loadDnsList;
  if (typeof window.loadDnsStats === 'function') window.TrueID.loadDnsStats = window.loadDnsStats;
  if (typeof window.loadDnsTab === 'function') window.TrueID.loadDnsTab = window.loadDnsTab;
  if (typeof window.loadFingerprintList === 'function') window.TrueID.loadFingerprintList = window.loadFingerprintList;
  if (typeof window.loadFingerprintObservations === 'function') window.TrueID.loadFingerprintObservations = window.loadFingerprintObservations;
  if (typeof window.loadFingerprintStats === 'function') window.TrueID.loadFingerprintStats = window.loadFingerprintStats;
  if (typeof window.loadFingerprintsTab === 'function') window.TrueID.loadFingerprintsTab = window.loadFingerprintsTab;
  if (typeof window.loadSubnetMappings === 'function') window.TrueID.loadSubnetMappings = window.loadSubnetMappings;
  if (typeof window.loadSubnetSelect === 'function') window.TrueID.loadSubnetSelect = window.loadSubnetSelect;
  if (typeof window.loadSubnets === 'function') window.TrueID.loadSubnets = window.loadSubnets;
  if (typeof window.loadSubnetsStats === 'function') window.TrueID.loadSubnetsStats = window.loadSubnetsStats;
  if (typeof window.loadSubnetsTab === 'function') window.TrueID.loadSubnetsTab = window.loadSubnetsTab;
  if (typeof window.loadSwitchPorts === 'function') window.TrueID.loadSwitchPorts = window.loadSwitchPorts;
  if (typeof window.loadSwitches === 'function') window.TrueID.loadSwitches = window.loadSwitches;
  if (typeof window.loadSwitchesStats === 'function') window.TrueID.loadSwitchesStats = window.loadSwitchesStats;
  if (typeof window.loadSwitchesTab === 'function') window.TrueID.loadSwitchesTab = window.loadSwitchesTab;
  if (typeof window.pollSwitch === 'function') window.TrueID.pollSwitch = window.pollSwitch;
  if (typeof window.promoteDiscoveredSubnet === 'function') window.TrueID.promoteDiscoveredSubnet = window.promoteDiscoveredSubnet;
  if (typeof window.runFingerprintBackfill === 'function') window.TrueID.runFingerprintBackfill = window.runFingerprintBackfill;
  if (typeof window.saveFingerprint === 'function') window.TrueID.saveFingerprint = window.saveFingerprint;
  if (typeof window.saveSubnet === 'function') window.TrueID.saveSubnet = window.saveSubnet;
  if (typeof window.saveSwitch === 'function') window.TrueID.saveSwitch = window.saveSwitch;
  if (typeof window.showFingerprintForm === 'function') window.TrueID.showFingerprintForm = window.showFingerprintForm;
  if (typeof window.showSubnetForm === 'function') window.TrueID.showSubnetForm = window.showSubnetForm;
  if (typeof window.showSwitchForm === 'function') window.TrueID.showSwitchForm = window.showSwitchForm;
  if (typeof window.toggleSubnetMappings === 'function') window.TrueID.toggleSubnetMappings = window.toggleSubnetMappings;
  if (typeof window.toggleSwitchPorts === 'function') window.TrueID.toggleSwitchPorts = window.toggleSwitchPorts;
})();
