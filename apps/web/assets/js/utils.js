/* Utility functions extracted from dashboard monolith. */

function escapeHtml(v) {
        if (v === null || v === undefined) return '';
        return String(v)
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;')
          .replace(/'/g, '&#039;');
      }

      function escJs(v) {
        if (v === null || v === undefined) return '';
        return String(v).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
      }

      function timeAgo(isoStr) {
        if (!isoStr || isoStr === '-') return '-';
        var diff = Date.now() - new Date(isoStr).getTime();
        if (diff < 0) return 'just now';
        var sec = Math.floor(diff / 1000);
        if (sec < 60) return sec + 's ago';
        var min = Math.floor(sec / 60);
        if (min < 60) return min + ' min ago';
        var hrs = Math.floor(min / 60);
        if (hrs < 24) return hrs + 'h ago';
        return Math.floor(hrs / 24) + 'd ago';
      }

      function badgeClass(sev) {
        if (sev === 'critical') return 'badge badge-critical';
        if (sev === 'warning') return 'badge badge-warning';
        return 'badge badge-info';
      }

      function yesNoBadge(v) {
        return v ? '<span class="check-yes">Yes</span>' : '<span class="check-no">No</span>';
      }

      function maskedDbUrl(v) {
        if (!v) return '-';
        var s = String(v);
        if (s.length <= 12) return '********';
        return s.slice(0, 8) + '********';
      }

      function statusDotClass(status) {
        if (status === 'listening') return 'online';
        if (status === 'starting') return 'badge-warning';
        return 'offline';
      }

      function formatGroups(groups) {
        if (!Array.isArray(groups) || groups.length === 0) return '-';
        if (groups.length <= 2) return escapeHtml(groups.join(', '));
        return escapeHtml(groups.slice(0, 2).join(', ')) + ' <span class="muted">+' + (groups.length - 2) + ' more</span>';
      }

      function webhookStatusView(status) {
        if (status === 'sent') return '<span class="wh-sent">✓ sent</span>';
        if (status === 'failed') return '<span class="wh-failed">✕ failed</span>';
        return '<span class="wh-skip">- ' + escapeHtml(status || 'no_webhook') + '</span>';
      }

      function countryCodeToFlag(cc) {
        if (!cc || cc.length !== 2) return '';
        var a = cc.toUpperCase().charCodeAt(0);
        var b = cc.toUpperCase().charCodeAt(1);
        if (a < 65 || a > 90 || b < 65 || b > 90) return '';
        return String.fromCodePoint(0x1F1E6 + (a - 65), 0x1F1E6 + (b - 65));
      }

      function renderTagsBadges(tags) {
        if (!Array.isArray(tags) || tags.length === 0) return '<span class="muted">-</span>';
        return tags.slice(0, 4).map(function (t) {
          var color = t && t.color ? t.color : 'var(--text-secondary)';
          var label = t && t.tag ? t.tag : '-';
          return '<span class="badge" style="margin-right:4px;border:1px solid ' + escapeHtml(color) + ';color:' + escapeHtml(color) + ';">' +
            escapeHtml(label) + '</span>';
        }).join('');
      }

      function renderPager(elId, page, perPage, total, fnName) {
        var totalPages = Math.ceil(total / perPage) || 1;
        var html = 'Page ' + page + ' of ' + totalPages + ' (' + total + ' items) &nbsp;';
        if (page > 1) html += '<button class="btn btn-sm" onclick="' + fnName + '(' + (page - 1) + ')">← Prev</button> ';
        if (page < totalPages) html += '<button class="btn btn-sm" onclick="' + fnName + '(' + (page + 1) + ')">Next →</button>';
        document.getElementById(elId).innerHTML = html;
      }

      function trimFingerprint(v) {
        if (!v) return '-';
        var s = String(v);
        return s.length > 30 ? escapeHtml(s.slice(0, 30)) + '…' : escapeHtml(s);
      }

      function flashElement(el, ok) {
        if (!el) return;
        el.classList.remove('flash-ok', 'flash-err');
        void el.offsetWidth;
        el.classList.add(ok ? 'flash-ok' : 'flash-err');
      }

      /**
       * Stores sort state per tab.
       * Returns: void.
       */
      window.sortState = window.sortState || {};

      /**
       * Toggles sort state for a table tab.
       * Parameters: tabName - logical tab key, column - selected sort key, reloadFn - tab reload callback.
       * Returns: void.
       */
      function handleSort(tabName, column, reloadFn) {
        var state = window.sortState[tabName] || {};
        if (state.column === column) {
          state.direction = state.direction === 'asc' ? 'desc' : 'asc';
        } else {
          state.column = column;
          state.direction = 'asc';
        }
        window.sortState[tabName] = state;
        reloadFn(1);
      }

      /**
       * Binds sortable behavior and active arrow state to table headers.
       * Parameters: tableId - table DOM id, tabName - logical tab key, _columnMap - reserved map, reloadFn - tab reload callback.
       * Returns: void.
       */
      function applySortHeaders(tableId, tabName, _columnMap, reloadFn) {
        var table = document.getElementById(tableId);
        if (!table) return;
        var ths = table.querySelectorAll('th');
        var state = window.sortState[tabName] || {};
        ths.forEach(function (th) {
          var col = th.getAttribute('data-sort');
          if (!col) return;
          th.classList.add('sortable');
          th.classList.remove('sort-asc', 'sort-desc');
          if (state.column === col) {
            th.classList.add(state.direction === 'desc' ? 'sort-desc' : 'sort-asc');
          }
          th.onclick = function () { handleSort(tabName, col, reloadFn); };
        });
      }

      /**
       * Builds query params for backend sorting.
       * Parameters: tabName - logical tab key.
       * Returns: query string fragment or empty string.
       */
      function getSortParams(tabName) {
        var state = window.sortState[tabName];
        if (!state || !state.column) return '';
        return '&sort=' + encodeURIComponent(state.column) + '&order=' + state.direction;
      }

(function () {
  window.TrueID = window.TrueID || {};
  if (typeof window.badgeClass === 'function') window.TrueID.badgeClass = window.badgeClass;
  if (typeof window.countryCodeToFlag === 'function') window.TrueID.countryCodeToFlag = window.countryCodeToFlag;
  if (typeof window.escJs === 'function') window.TrueID.escJs = window.escJs;
  if (typeof window.escapeHtml === 'function') window.TrueID.escapeHtml = window.escapeHtml;
  if (typeof window.flashElement === 'function') window.TrueID.flashElement = window.flashElement;
  if (typeof window.formatGroups === 'function') window.TrueID.formatGroups = window.formatGroups;
  if (typeof window.maskedDbUrl === 'function') window.TrueID.maskedDbUrl = window.maskedDbUrl;
  if (typeof window.getSortParams === 'function') window.TrueID.getSortParams = window.getSortParams;
  if (typeof window.handleSort === 'function') window.TrueID.handleSort = window.handleSort;
  if (typeof window.applySortHeaders === 'function') window.TrueID.applySortHeaders = window.applySortHeaders;
  if (typeof window.renderPager === 'function') window.TrueID.renderPager = window.renderPager;
  if (typeof window.renderTagsBadges === 'function') window.TrueID.renderTagsBadges = window.renderTagsBadges;
  if (typeof window.statusDotClass === 'function') window.TrueID.statusDotClass = window.statusDotClass;
  if (typeof window.timeAgo === 'function') window.TrueID.timeAgo = window.timeAgo;
  if (typeof window.trimFingerprint === 'function') window.TrueID.trimFingerprint = window.trimFingerprint;
  if (typeof window.webhookStatusView === 'function') window.TrueID.webhookStatusView = window.webhookStatusView;
  if (typeof window.yesNoBadge === 'function') window.TrueID.yesNoBadge = window.yesNoBadge;
})();
