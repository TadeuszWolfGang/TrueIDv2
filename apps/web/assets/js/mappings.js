/* Mappings and search module. */

function parseSearchToFilter(search) {
        var out = {};
        if (!search) return out;
        if (/^\d{1,3}(\.\d{1,3}){3}$/.test(search)) {
          out.ip = search;
        } else if (/^[0-9a-fA-F:\-]{11,}$/.test(search)) {
          out.mac = search;
        } else if (/^[a-zA-Z0-9._@-]{2,}$/.test(search)) {
          out.user = search;
        } else {
          out.q = search;
        }
        return out;
      }

      async function loadMappingsStats() {
        try {
          var res = await fetch('/api/v1/stats', { credentials: 'include' });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          var data = await res.json();
          var total = data.total_mappings || data.total || 0;
          var active = data.active_mappings || data.active || 0;
          var inactive = data.inactive_mappings || Math.max(0, total - active);
          var sources = '';
          if (data.source_counts && typeof data.source_counts === 'object') {
            sources = Object.keys(data.source_counts).map(function (k) {
              return k + ': ' + data.source_counts[k];
            }).join(', ');
          }
          document.getElementById('mappings-stats').innerHTML =
            '<span>Total: <strong>' + total + '</strong></span>' +
            '<span>Active: <strong>' + active + '</strong></span>' +
            '<span>Inactive: <strong>' + inactive + '</strong></span>' +
            '<span>Sources: <strong>' + escapeHtml(sources || 'n/a') + '</strong></span>';
        } catch (e) {
          document.getElementById('mappings-stats').innerHTML =
            '<span class="muted">No stats available.</span>';
        }
      }

      function renderMappingsTable(items) {
        var body = document.getElementById('mappings-body');
        if (!items || items.length === 0) {
          body.innerHTML = '<tr><td colspan="10" class="muted">No mappings found.</td></tr>';
          applySortHeaders('mappings-table', 'mappings', null, loadMappings);
          return;
        }
        body.innerHTML = items.map(function (item) {
          var active = item.is_active !== false;
          var cls = active ? '' : 'offline';
          var dotCls = active ? 'online' : 'offline';
          var ip = item.ip || '-';
          var mac = item.mac || '-';
          var vendor = item.vendor ? '<span class="vendor">' + escapeHtml(item.vendor) + '</span>' : '';
          var users = Array.isArray(item.current_users) ? item.current_users : [];
          var user = users.length ? users.join(', ') : '-';
          var userPrimary = users.length ? users[0] : (item.user || '-');
          var groups = formatGroups(item.groups);
          var location = item.country_code
            ? ((countryCodeToFlag(item.country_code) ? countryCodeToFlag(item.country_code) + ' ' : '') +
              (item.city || item.country_code))
            : (item.city === 'Private' ? 'Private' : '-');
          var tags = renderTagsBadges(item.tags);
          var multiBadge = item.multi_user ? '<span class="multi-badge">🖥 multi</span>' : '';
          var source = item.source || '-';
          var confidence = item.confidence_score != null ? item.confidence_score : '-';
          return '<tr class="' + cls + '">' +
            '<td><span class="dot ' + dotCls + '"></span></td>' +
            '<td><a href="#" class="ip-link" onclick="openTimeline(\'ip\', \'' + escJs(ip) + '\');return false;">' + escapeHtml(ip) + '</a></td>' +
            '<td>' + escapeHtml(mac) + vendor + '</td>' +
            '<td><a href="#" class="ip-link" onclick="openTimeline(\'user\', \'' + escJs(userPrimary) + '\');return false;">' + escapeHtml(user) + '</a>' + multiBadge + '</td>' +
            '<td>' + groups + '</td>' +
            '<td>' + escapeHtml(location) + '</td>' +
            '<td>' + tags + '</td>' +
            '<td>' + escapeHtml(timeAgo(item.last_seen)) + '</td>' +
            '<td>' + escapeHtml(source) + '</td>' +
            '<td>' + escapeHtml(confidence) + '</td>' +
            '</tr>';
        }).join('');
        applySortHeaders('mappings-table', 'mappings', null, loadMappings);
      }

      function renderMappingsPaging(page, perPage, total) {
        var totalPages = Math.ceil(total / perPage) || 1;
        var el = document.getElementById('mappings-paging');
        var html = 'Page ' + page + ' of ' + totalPages + ' (' + total + ' mappings) &nbsp;';
        if (page > 1) html += '<button class="btn btn-sm" onclick="loadMappings(' + (page - 1) + ')">← Prev</button> ';
        if (page < totalPages) html += '<button class="btn btn-sm" onclick="loadMappings(' + (page + 1) + ')">Next →</button>';
        el.innerHTML = html;
      }

      async function loadMappings(page) {
        mappingsCurrentPage = page || 1;
        var status = document.getElementById('mappings-status');
        var search = document.getElementById('mappings-search').value;
        var source = document.getElementById('mappings-source').value;
        var active = document.getElementById('mappings-active').value;
        var params = new URLSearchParams({
          scope: 'mappings',
          page: String(mappingsCurrentPage),
          limit: String(mappingsPerPage)
        });
        if (search) params.set('q', search);
        if (source) params.set('source', source);
        if (active !== '') params.set('active', active);
        if (!window.sortState || !window.sortState.mappings || !window.sortState.mappings.column) {
          params.set('sort', 'last_seen');
          params.set('order', 'desc');
        }
        var sortParams = getSortParams('mappings');
        if (sortParams) {
          var sortQuery = new URLSearchParams(sortParams.slice(1));
          sortQuery.forEach(function (value, key) { params.set(key, value); });
        }

        try {
          var res = await fetch('/api/v2/search?' + params.toString(), { credentials: 'include' });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          var data = await res.json();
          var section = data.mappings || { data: [], total: 0 };
          renderMappingsTable(section.data || []);
          renderMappingsPaging(data.page || mappingsCurrentPage, data.limit || mappingsPerPage, section.total || 0);
          status.textContent = 'Last update: ' + new Date().toLocaleTimeString();
          loadMappingsStats();
        } catch (err) {
          document.getElementById('mappings-body').innerHTML =
            '<tr><td colspan="10" style="color:var(--status-error);">Failed: ' + escapeHtml(err.message) + '</td></tr>';
          status.textContent = 'Last update failed';
        }
      }

      function exportMappings(format) {
        var search = document.getElementById('mappings-search').value;
        var source = document.getElementById('mappings-source').value;
        var active = document.getElementById('mappings-active').value;
        var params = new URLSearchParams({ format: format });
        var parsed = parseSearchToFilter(search);
        if (parsed.ip) params.set('ip', parsed.ip);
        if (parsed.user) params.set('user', parsed.user);
        if (parsed.mac) params.set('mac', parsed.mac);
        if (parsed.q) params.set('q', parsed.q);
        if (source) params.set('source', source);
        if (active !== '') params.set('active', active);
        window.location = '/api/v2/export/mappings?' + params.toString();
      }

      function exportEvents(format) {
        var params = new URLSearchParams({ format: format });
        var ip = document.getElementById('search-ip').value.trim();
        var user = document.getElementById('search-user').value.trim();
        var source = document.getElementById('search-source').value;
        if (ip) params.set('ip', ip);
        if (user) params.set('user', user);
        if (source) params.set('source', source);
        window.location = '/api/v2/export/events?' + params.toString();
      }

      function renderSearchPaging(page, perPage, total) {
        var totalPages = Math.ceil(total / perPage) || 1;
        var el = document.getElementById('search-paging');
        var html = 'Page ' + page + ' of ' + totalPages + ' (' + total + ' results) &nbsp;';
        if (page > 1) html += '<button class="btn btn-sm" onclick="doSearch(' + (page - 1) + ')">← Prev</button> ';
        if (page < totalPages) html += '<button class="btn btn-sm" onclick="doSearch(' + (page + 1) + ')">Next →</button>';
        el.innerHTML = html;
      }

      async function doSearch(page) {
        searchCurrentPage = page || 1;
        var params = new URLSearchParams({
          page: String(searchCurrentPage),
          limit: String(searchPerPage)
        });
        var q = document.getElementById('search-q').value;
        var ip = document.getElementById('search-ip').value.trim();
        var user = document.getElementById('search-user').value.trim();
        var mac = document.getElementById('search-mac').value.trim();
        var source = document.getElementById('search-source').value;
        var scope = document.getElementById('search-scope').value;
        if (q) params.set('q', q);
        if (ip) params.set('ip', ip);
        if (user) params.set('user', user);
        if (mac) params.set('mac', mac);
        if (source) params.set('source', source);
        if (scope) params.set('scope', scope);
        if (!window.sortState || !window.sortState.search || !window.sortState.search.column) {
          params.set('sort', 'timestamp');
          params.set('order', 'desc');
        }
        var sortParams = getSortParams('search');
        if (sortParams) {
          var sortQuery = new URLSearchParams(sortParams.slice(1));
          sortQuery.forEach(function (value, key) { params.set(key, value); });
        }

        var mappingsSection = document.getElementById('search-mappings-section');
        var eventsSection = document.getElementById('search-events-section');
        var mappingsBody = document.getElementById('search-mappings-body');
        var eventsBody = document.getElementById('search-events-body');

        try {
          var res = await fetch('/api/v2/search?' + params.toString(), { credentials: 'include' });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          var data = await res.json();
          var mappings = data.mappings;
          var events = data.events;
          var mappingsTotal = mappings ? (mappings.total || 0) : 0;
          var eventsTotal = events ? (events.total || 0) : 0;
          var maxTotal = Math.max(mappingsTotal, eventsTotal);

          if (mappings) {
            mappingsSection.style.display = '';
            document.getElementById('search-mappings-count').textContent = '(' + mappingsTotal + ')';
            var list = mappings.data || [];
            mappingsBody.innerHTML = list.length ? list.map(function (item) {
              var ipVal = item.ip || '-';
              var users = Array.isArray(item.current_users) ? item.current_users : [];
              var userVal = users.length ? users.join(', ') : '-';
              var userPrimary = users.length ? users[0] : (item.user || '-');
              var groups = formatGroups(item.groups);
              var multiBadge = item.multi_user ? '<span class="multi-badge">🖥 multi</span>' : '';
              return '<tr>' +
                '<td><span class="dot ' + (item.is_active === false ? 'offline' : 'online') + '"></span></td>' +
                '<td><a href="#" class="ip-link" onclick="openTimeline(\'ip\', \'' + escJs(ipVal) + '\');return false;">' + escapeHtml(ipVal) + '</a></td>' +
                '<td>' + escapeHtml(item.mac || '-') + '</td>' +
                '<td><a href="#" class="ip-link" onclick="openTimeline(\'user\', \'' + escJs(userPrimary) + '\');return false;">' + escapeHtml(userVal) + '</a>' + multiBadge + '</td>' +
                '<td>' + groups + '</td>' +
                '<td>' + escapeHtml(timeAgo(item.last_seen)) + '</td>' +
                '<td>' + escapeHtml(item.source || '-') + '</td>' +
                '<td>' + escapeHtml(item.confidence_score != null ? item.confidence_score : '-') + '</td>' +
                '</tr>';
            }).join('') : '<tr><td colspan="8" class="muted">No mappings found.</td></tr>';
            applySortHeaders('search-mappings-table', 'search', null, doSearch);
          } else {
            mappingsSection.style.display = 'none';
          }

          if (events) {
            eventsSection.style.display = '';
            document.getElementById('search-events-count').textContent = '(' + eventsTotal + ')';
            var elist = events.data || [];
            eventsBody.innerHTML = elist.length ? elist.map(function (e) {
              return '<tr>' +
                '<td>' + escapeHtml(e.id || '-') + '</td>' +
                '<td><a href="#" class="ip-link" onclick="openTimeline(\'ip\', \'' + escJs(e.ip || '') + '\');return false;">' + escapeHtml(e.ip || '-') + '</a></td>' +
                '<td><a href="#" class="ip-link" onclick="openTimeline(\'user\', \'' + escJs(e.user || '') + '\');return false;">' + escapeHtml(e.user || '-') + '</a></td>' +
                '<td>' + escapeHtml(e.source || '-') + '</td>' +
                '<td>' + escapeHtml(new Date(e.timestamp).toLocaleString()) + '</td>' +
                '</tr>';
            }).join('') : '<tr><td colspan="5" class="muted">No events found.</td></tr>';
            applySortHeaders('search-events-table', 'search', null, doSearch);
          } else {
            eventsSection.style.display = 'none';
          }

          renderSearchPaging(data.page || searchCurrentPage, data.limit || searchPerPage, maxTotal);
          document.getElementById('search-meta').textContent =
            'Found ' + mappingsTotal + ' mappings + ' + eventsTotal + ' events in ' + (data.query_time_ms || 0) + 'ms';
        } catch (err) {
          mappingsSection.style.display = '';
          eventsSection.style.display = 'none';
          mappingsBody.innerHTML = '<tr><td colspan="8" style="color:var(--status-error);">Search failed: ' + escapeHtml(err.message) + '</td></tr>';
          document.getElementById('search-meta').textContent = '';
          document.getElementById('search-paging').innerHTML = '';
        }
      }

      async function openTimeline(type, value) {
        var panel = document.getElementById('timeline-panel');
        var title = document.getElementById('timeline-title');
        var content = document.getElementById('timeline-content');
        panel.style.display = 'block';
        panel.classList.remove('timeline-enter');
        void panel.offsetWidth;
        panel.classList.add('timeline-enter');
        title.textContent = 'Timeline :: ' + type + ' :: ' + value;
        content.innerHTML = '<span class="muted">Loading...</span>';
        try {
          var res = await fetch('/api/v2/timeline/' + encodeURIComponent(type) + '/' + encodeURIComponent(value), {
            credentials: 'include'
          });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          var data = await res.json();
          if (type === 'ip') {
            var mapping = data.current_mapping;
            var html = '';
            html += '<div class="panel" style="padding:12px;margin-bottom:12px;">';
            html += '<div style="margin-bottom:8px;"><strong>Conflicts:</strong> <span class="' + badgeClass((data.conflicts_count || 0) > 0 ? 'warning' : 'info') + '">' + (data.conflicts_count || 0) + '</span></div>';
            if (mapping) {
              html += '<div><strong>User:</strong> <a href="#" class="ip-link" onclick="openTimeline(\'user\', \'' + escJs(mapping.user || '') + '\');return false;">' + escapeHtml(mapping.user || '-') + '</a></div>';
              html += '<div><strong>MAC:</strong> ' + escapeHtml(mapping.mac || '-') + '</div>';
              html += '<div><strong>Source:</strong> ' + escapeHtml(mapping.source || '-') + '</div>';
              html += '<div><strong>Last Seen:</strong> ' + escapeHtml(new Date(mapping.last_seen).toLocaleString()) + '</div>';
              try {
                var tagsResp = await fetch('/api/v2/tags/ip/' + encodeURIComponent(value), { credentials: 'include' });
                if (tagsResp.ok) {
                  var tagsBody = await tagsResp.json();
                  var tags = tagsBody.data || [];
                  html += '<div><strong>Tags:</strong> ' + (tags.length ? renderTagsBadges(tags) : '<span class="muted">-</span>') + '</div>';
                }
              } catch (eTags) {}
            } else {
              html += '<div class="muted">No current mapping.</div>';
            }
            html += '</div>';

            html += '<h3 class="section-title">User changes</h3>';
            if (data.user_changes && data.user_changes.length) {
              html += '<ul style="padding-left:16px;margin-top:6px;">' +
                data.user_changes.map(function (c) {
                  return '<li><a href="#" class="ip-link" onclick="openTimeline(\'user\', \'' + escJs(c.from_user) + '\');return false;">' + escapeHtml(c.from_user) +
                    '</a> → <a href="#" class="ip-link" onclick="openTimeline(\'user\', \'' + escJs(c.to_user) + '\');return false;">' + escapeHtml(c.to_user) +
                    '</a> <span class="muted">(' + escapeHtml(new Date(c.changed_at).toLocaleString()) + ', ' + escapeHtml(c.source || '-') + ')</span></li>';
                }).join('') + '</ul>';
            } else {
              html += '<div class="muted">No user transitions.</div>';
            }

            html += '<h3 class="section-title">Recent events</h3>';
            if (data.events && data.events.data && data.events.data.length) {
              html += '<ul style="padding-left:16px;margin-top:6px;">' +
                data.events.data.map(function (e) {
                  return '<li><a href="#" class="ip-link" onclick="openTimeline(\'user\', \'' + escJs(e.user) + '\');return false;">' + escapeHtml(e.user) +
                    '</a> <span class="muted">(' + escapeHtml(e.source || '-') + ', ' + escapeHtml(new Date(e.timestamp).toLocaleString()) + ')</span></li>';
                }).join('') + '</ul>';
            } else {
              html += '<div class="muted">No events.</div>';
            }
            content.innerHTML = html;
          } else if (type === 'user') {
            var html2 = '<h3 class="section-title">Active mappings</h3>';
            if (data.active_mappings && data.active_mappings.length) {
              html2 += '<ul style="padding-left:16px;margin-top:6px;">' +
                data.active_mappings.map(function (m) {
                  return '<li><a href="#" class="ip-link" onclick="openTimeline(\'ip\', \'' + escJs(m.ip) + '\');return false;">' + escapeHtml(m.ip) + '</a> ' +
                    '<span class="muted">(' + escapeHtml(m.source || '-') + ', ' + escapeHtml(timeAgo(m.last_seen)) + ')</span></li>';
                }).join('') + '</ul>';
            } else {
              html2 += '<div class="muted">No active mappings.</div>';
            }
            html2 += '<h3 class="section-title">IP addresses used</h3>';
            if (data.ip_addresses_used && data.ip_addresses_used.length) {
              html2 += '<div style="display:flex;flex-wrap:wrap;gap:6px;">' +
                data.ip_addresses_used.map(function (ip) {
                  return '<a href="#" class="ip-link" onclick="openTimeline(\'ip\', \'' + escJs(ip) + '\');return false;">' + escapeHtml(ip) + '</a>';
                }).join(' ') + '</div>';
            } else {
              html2 += '<div class="muted">No IP history.</div>';
            }
            html2 += '<h3 class="section-title">Recent events</h3>';
            if (data.events && data.events.data && data.events.data.length) {
              html2 += '<ul style="padding-left:16px;margin-top:6px;">' +
                data.events.data.map(function (e) {
                  return '<li><a href="#" class="ip-link" onclick="openTimeline(\'ip\', \'' + escJs(e.ip) + '\');return false;">' + escapeHtml(e.ip) +
                    '</a> <span class="muted">(' + escapeHtml(e.source || '-') + ', ' + escapeHtml(new Date(e.timestamp).toLocaleString()) + ')</span></li>';
                }).join('') + '</ul>';
            } else {
              html2 += '<div class="muted">No events.</div>';
            }
            content.innerHTML = html2;
          } else {
            content.innerHTML = '<pre style="white-space:pre-wrap;">' + escapeHtml(JSON.stringify(data, null, 2)) + '</pre>';
          }
        } catch (err) {
          content.innerHTML = '<span style="color:var(--status-error);">Failed to load timeline: ' + escapeHtml(err.message) + '</span>';
        }
      }

      function closeTimeline() {
        document.getElementById('timeline-panel').style.display = 'none';
      }

(function () {
  window.TrueID = window.TrueID || {};
  if (typeof window.closeTimeline === 'function') window.TrueID.closeTimeline = window.closeTimeline;
  if (typeof window.doSearch === 'function') window.TrueID.doSearch = window.doSearch;
  if (typeof window.exportEvents === 'function') window.TrueID.exportEvents = window.exportEvents;
  if (typeof window.exportMappings === 'function') window.TrueID.exportMappings = window.exportMappings;
  if (typeof window.loadMappings === 'function') window.TrueID.loadMappings = window.loadMappings;
  if (typeof window.loadMappingsStats === 'function') window.TrueID.loadMappingsStats = window.loadMappingsStats;
  if (typeof window.openTimeline === 'function') window.TrueID.openTimeline = window.openTimeline;
  if (typeof window.parseSearchToFilter === 'function') window.TrueID.parseSearchToFilter = window.parseSearchToFilter;
  if (typeof window.renderMappingsPaging === 'function') window.TrueID.renderMappingsPaging = window.renderMappingsPaging;
  if (typeof window.renderMappingsTable === 'function') window.TrueID.renderMappingsTable = window.renderMappingsTable;
  if (typeof window.renderSearchPaging === 'function') window.TrueID.renderSearchPaging = window.renderSearchPaging;
})();
