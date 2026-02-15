/* Conflicts module. */

async function loadConflictsStats() {
        try {
          var res = await fetch('/api/v2/conflicts/stats', { credentials: 'include' });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          var s = await res.json();
          document.getElementById('conflicts-stats').innerHTML =
            '<span>Unresolved: <strong>' + (s.total_unresolved || 0) + '</strong></span>' +
            '<span>IP Changes: <strong>' + ((s.by_type && s.by_type.ip_user_change) || 0) + '</strong></span>' +
            '<span>MAC Conflicts: <strong>' + ((s.by_type && s.by_type.mac_ip_conflict) || 0) + '</strong></span>' +
            '<span>Duplicate MACs: <strong>' + ((s.by_type && s.by_type.duplicate_mac) || 0) + '</strong></span>';
        } catch (e) {
          document.getElementById('conflicts-stats').innerHTML = '<span class="muted">No data available.</span>';
        }
      }

      function renderConflictsPaging(page, perPage, total) {
        var totalPages = Math.ceil(total / perPage) || 1;
        var el = document.getElementById('conflicts-paging');
        var html = 'Page ' + page + ' of ' + totalPages + ' (' + total + ' conflicts) &nbsp;';
        if (page > 1) html += '<button class="btn btn-sm" onclick="loadConflicts(' + (page - 1) + ')">← Prev</button> ';
        if (page < totalPages) html += '<button class="btn btn-sm" onclick="loadConflicts(' + (page + 1) + ')">Next →</button>';
        el.innerHTML = html;
      }

      async function loadConflicts(page) {
        conflictsCurrentPage = page || 1;
        var type = document.getElementById('conflict-type').value;
        var severity = document.getElementById('conflict-severity').value;
        var resolved = document.getElementById('conflict-resolved').value;
        var params = new URLSearchParams({ page: String(conflictsCurrentPage), limit: '50' });
        if (type) params.set('type', type);
        if (severity) params.set('severity', severity);
        if (resolved !== '') params.set('resolved', resolved);
        if (!window.sortState || !window.sortState.conflicts || !window.sortState.conflicts.column) {
          params.set('sort', 'detected_at');
          params.set('order', 'desc');
        }
        var sortParams = getSortParams('conflicts');
        if (sortParams) {
          var sortQuery = new URLSearchParams(sortParams.slice(1));
          sortQuery.forEach(function (value, key) { params.set(key, value); });
        }

        try {
          var res = await fetch('/api/v2/conflicts?' + params.toString(), { credentials: 'include' });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          var data = await res.json();
          var rows = data.data || [];
          var body = document.getElementById('conflicts-body');
          if (!rows.length) {
            body.innerHTML = '<tr><td colspan="8" class="muted">No data available.</td></tr>';
          } else {
            body.innerHTML = rows.map(function (c) {
              var userPair = (c.user_old || '-') + ' → ' + (c.user_new || '-');
              var canResolve = currentUser && currentUser.role !== 'Viewer' && !c.resolved_at;
              var action = canResolve
                ? '<button class="btn btn-sm" onclick="resolveConflict(' + c.id + ')">Resolve</button>'
                : '<span class="muted">' + (c.resolved_at ? 'Resolved' : '-') + '</span>';
              return '<tr>' +
                '<td><span class="' + badgeClass(c.severity) + '">' + escapeHtml(c.severity) + '</span></td>' +
                '<td>' + escapeHtml(c.conflict_type || '-') + '</td>' +
                '<td>' + (c.ip ? '<a href="#" class="ip-link" onclick="openTimeline(\'ip\', \'' + escJs(c.ip) + '\');return false;">' + escapeHtml(c.ip) + '</a>' : '-') + '</td>' +
                '<td>' + escapeHtml(userPair) + '</td>' +
                '<td>' + escapeHtml(c.mac || '-') + '</td>' +
                '<td>' + escapeHtml(c.source || '-') + '</td>' +
                '<td>' + escapeHtml(new Date(c.detected_at).toLocaleString()) + '</td>' +
                '<td>' + action + '</td>' +
                '</tr>';
            }).join('');
          }
          applySortHeaders('conflicts-table', 'conflicts', null, loadConflicts);
          renderConflictsPaging(data.page || conflictsCurrentPage, data.limit || 50, data.total || 0);
        } catch (err) {
          document.getElementById('conflicts-body').innerHTML =
            '<tr><td colspan="8" class="muted">No data available.</td></tr>';
          document.getElementById('conflicts-paging').innerHTML = '';
        }
      }

      async function resolveConflict(id) {
        var note = window.prompt('Resolution note (optional):', '') || '';
        try {
          var res = await fetch('/api/v2/conflicts/' + encodeURIComponent(id) + '/resolve', {
            method: 'POST',
            headers: mutHeaders(),
            credentials: 'include',
            body: JSON.stringify({ note: note || null })
          });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          loadConflictsStats();
          loadConflicts(conflictsCurrentPage);
        } catch (err) {
          alert('Resolve failed: ' + err.message);
        }
      }

(function () {
  window.TrueID = window.TrueID || {};
  if (typeof window.loadConflicts === 'function') window.TrueID.loadConflicts = window.loadConflicts;
  if (typeof window.loadConflictsStats === 'function') window.TrueID.loadConflictsStats = window.loadConflictsStats;
  if (typeof window.renderConflictsPaging === 'function') window.TrueID.renderConflictsPaging = window.renderConflictsPaging;
  if (typeof window.resolveConflict === 'function') window.TrueID.resolveConflict = window.resolveConflict;
})();
