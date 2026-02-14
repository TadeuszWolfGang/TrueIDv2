/* Analytics module. */

function renderBarChart(containerId, data, color) {
        var el = document.getElementById(containerId);
        if (!el) return;
        if (!Array.isArray(data) || data.length === 0) {
          el.innerHTML = '<span class="muted">No data.</span>';
          return;
        }
        var max = Math.max.apply(null, data.map(function (d) { return d.count || 0; }).concat([1]));
        var barWidth = 40;
        var gap = 8;
        var height = 120;
        var width = data.length * (barWidth + gap);
        var axisColor = themeColor('--border-dim');
        var labelColor = themeColor('--text-secondary');
        var valueColor = themeColor('--text-primary');
        var svg = '<svg width="' + width + '" height="' + (height + 30) + '">';
        svg += '<line x1="0" y1="' + height + '" x2="' + width + '" y2="' + height + '" stroke="' + axisColor + '" stroke-width="1"/>';
        data.forEach(function (d, i) {
          var count = d.count || 0;
          var barH = (count / max) * height;
          var x = i * (barWidth + gap);
          var y = height - barH;
          var label = String(d.timestamp || '').slice(5, 10);
          svg += '<rect x="' + x + '" y="' + y + '" width="' + barWidth + '" height="' + barH + '" fill="' + color + '" rx="3"/>';
          svg += '<text x="' + (x + barWidth / 2) + '" y="' + (height + 16) + '" fill="' + labelColor + '" font-size="11" text-anchor="middle">' + escapeHtml(label) + '</text>';
          svg += '<text x="' + (x + barWidth / 2) + '" y="' + (y - 4) + '" fill="' + valueColor + '" font-size="11" text-anchor="middle">' + count + '</text>';
        });
        svg += '</svg>';
        el.innerHTML = svg;
      }

      function renderDonutChart(containerId, rows) {
        var el = document.getElementById(containerId);
        if (!el) return;
        if (!Array.isArray(rows) || rows.length === 0) {
          el.innerHTML = '<span class="muted">No source distribution data.</span>';
          return;
        }
        var total = rows.reduce(function (acc, r) { return acc + (r.count || 0); }, 0) || 1;
        var radius = 56;
        var circ = 2 * Math.PI * radius;
        var colors = [
          themeColor('--green-mid'),
          themeColor('--status-info'),
          themeColor('--status-warn'),
          themeColor('--status-error'),
          'mediumpurple'
        ];
        var offset = 0;
        var svg = '<svg width="180" height="180" viewBox="0 0 180 180">';
        rows.forEach(function (r, idx) {
          var frac = (r.count || 0) / total;
          var seg = frac * circ;
          svg += '<circle cx="90" cy="90" r="' + radius + '" fill="none" stroke="' + colors[idx % colors.length] + '" stroke-width="22" stroke-dasharray="' + seg + ' ' + (circ - seg) + '" stroke-dashoffset="' + (-offset) + '" transform="rotate(-90 90 90)"/>';
          offset += seg;
        });
        svg += '<circle cx="90" cy="90" r="35" fill="' + themeColor('--bg-panel') + '"></circle>';
        svg += '<text x="90" y="92" fill="' + themeColor('--text-primary') + '" font-size="12" text-anchor="middle">' + total + '</text>';
        svg += '<text x="90" y="107" fill="' + themeColor('--text-secondary') + '" font-size="10" text-anchor="middle">events</text>';
        svg += '</svg>';
        var legend = '<div style="display:flex;flex-direction:column;gap:4px;">' + rows.map(function (r, idx) {
          return '<div><span style="display:inline-block;width:10px;height:10px;background:' + colors[idx % colors.length] + ';margin-right:6px;border-radius:2px;"></span>' +
            escapeHtml(r.source || '-') + ': <strong>' + (r.count || 0) + '</strong> (' + (r.percentage || 0) + '%)</div>';
        }).join('') + '</div>';
        el.innerHTML = '<div style="display:flex;gap:18px;align-items:center;flex-wrap:wrap;">' + svg + legend + '</div>';
      }

      function complianceCard(label, value, color) {
        return '<div class="stat-card" style="min-width:180px;">' +
          '<div class="muted" style="font-size:11px;">' + escapeHtml(label) + '</div>' +
          '<div style="font-size:20px;color:' + color + ';font-weight:700;">' + escapeHtml(value) + '</div>' +
          '</div>';
      }

      async function loadAnalyticsTab() {
        await Promise.all([
          loadAnalyticsTrends(),
          loadAnalyticsSources(),
          loadAnalyticsCompliance(),
          loadAnalyticsReports()
        ]);
      }

      async function loadAnalyticsTrends() {
        var metrics = [
          { metric: 'events', id: 'analytics-trend-events', color: themeColor('--green-mid') },
          { metric: 'conflicts', id: 'analytics-trend-conflicts', color: themeColor('--status-warn') },
          { metric: 'alerts', id: 'analytics-trend-alerts', color: themeColor('--status-error') }
        ];
        await Promise.all(metrics.map(async function (cfg) {
          try {
            var res = await fetch('/api/v2/analytics/trends?metric=' + encodeURIComponent(cfg.metric) + '&interval=day&days=7', { credentials: 'include' });
            if (!res.ok) throw new Error('HTTP ' + res.status);
            var data = await res.json();
            renderBarChart(cfg.id, data.data || [], cfg.color);
          } catch (e) {
            document.getElementById(cfg.id).innerHTML = '<span style="color:var(--status-error);">Failed: ' + escapeHtml(e.message) + '</span>';
          }
        }));
      }

      async function loadAnalyticsSources() {
        try {
          var res = await fetch('/api/v2/analytics/sources?days=7', { credentials: 'include' });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          var data = await res.json();
          renderDonutChart('analytics-sources-chart', data.sources || []);
        } catch (e) {
          document.getElementById('analytics-sources-chart').innerHTML = '<span style="color:var(--status-error);">Failed: ' + escapeHtml(e.message) + '</span>';
        }
      }

      async function loadAnalyticsCompliance() {
        try {
          var res = await fetch('/api/v2/analytics/compliance', { credentials: 'include' });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          var c = await res.json();
          var unresolved = (c.conflicts && c.conflicts.total_unresolved) || 0;
          var stale = (c.mappings && c.mappings.stale_24h) || 0;
          var fwOk = c.integrations && c.integrations.firewall_last_push_ok;
          var ldapOk = c.integrations && c.integrations.ldap_last_sync_ok;
          var cards =
            complianceCard('Active Mappings', (c.mappings && c.mappings.active) || 0, 'var(--status-ok)') +
            complianceCard('Unresolved Conflicts', unresolved, unresolved > 0 ? 'var(--status-error)' : 'var(--status-ok)') +
            complianceCard('Stale 24h', stale, stale > 10 ? 'var(--status-warn)' : 'var(--text-primary)') +
            complianceCard('IPs Without Subnet', (c.coverage && c.coverage.ips_without_subnet) || 0, 'var(--text-primary)') +
            complianceCard('Firewall Status', fwOk ? 'OK' : 'Issue', fwOk ? 'var(--status-ok)' : 'var(--status-error)') +
            complianceCard('LDAP Status', ldapOk ? 'OK' : 'Issue', ldapOk ? 'var(--status-ok)' : 'var(--status-error)');
          document.getElementById('analytics-compliance-cards').innerHTML = cards;
        } catch (e) {
          document.getElementById('analytics-compliance-cards').innerHTML = '<span style="color:var(--status-error);">Failed: ' + escapeHtml(e.message) + '</span>';
        }
      }

      async function loadAnalyticsReports() {
        try {
          var res = await fetch('/api/v2/analytics/reports?type=daily&limit=10', { credentials: 'include' });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          var data = await res.json();
          var rows = data.data || [];
          var body = document.getElementById('analytics-reports-body');
          if (!rows.length) {
            body.innerHTML = '<tr><td colspan="4" class="muted">No snapshots yet.</td></tr>';
            return;
          }
          body.innerHTML = rows.map(function (r) {
            var period = (r.period_start || '').slice(0, 10) + ' → ' + (r.period_end || '').slice(0, 10);
            return '<tr class="expand-row" onclick="openAnalyticsReport(' + r.id + ')">' +
              '<td>' + escapeHtml((r.generated_at || '').replace('T', ' ').replace('Z', '')) + '</td>' +
              '<td>' + escapeHtml(r.report_type || '-') + '</td>' +
              '<td>' + escapeHtml(period) + '</td>' +
              '<td>' + escapeHtml(r.summary || '-') + '</td>' +
              '</tr>';
          }).join('');
        } catch (e) {
          document.getElementById('analytics-reports-body').innerHTML =
            '<tr><td colspan="4" style="color:var(--status-error);">Failed: ' + escapeHtml(e.message) + '</td></tr>';
        }
      }

      async function openAnalyticsReport(id) {
        try {
          var res = await fetch('/api/v2/analytics/reports/' + encodeURIComponent(id), { credentials: 'include' });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          var data = await res.json();
          document.getElementById('analytics-report-json').textContent = JSON.stringify(data.data || data, null, 2);
          document.getElementById('analytics-report-modal').style.display = '';
        } catch (e) {
          alert('Failed to load report: ' + e.message);
        }
      }

      function closeAnalyticsReportModal() {
        document.getElementById('analytics-report-modal').style.display = 'none';
      }

      async function generateAnalyticsReport() {
        try {
          var res = await fetch('/api/v2/analytics/reports/generate', {
            method: 'POST',
            headers: mutHeaders(),
            credentials: 'include'
          });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          await loadAnalyticsReports();
        } catch (e) {
          alert('Generate failed: ' + e.message);
        }
      }

(function () {
  window.TrueID = window.TrueID || {};
  if (typeof window.closeAnalyticsReportModal === 'function') window.TrueID.closeAnalyticsReportModal = window.closeAnalyticsReportModal;
  if (typeof window.complianceCard === 'function') window.TrueID.complianceCard = window.complianceCard;
  if (typeof window.generateAnalyticsReport === 'function') window.TrueID.generateAnalyticsReport = window.generateAnalyticsReport;
  if (typeof window.loadAnalyticsCompliance === 'function') window.TrueID.loadAnalyticsCompliance = window.loadAnalyticsCompliance;
  if (typeof window.loadAnalyticsReports === 'function') window.TrueID.loadAnalyticsReports = window.loadAnalyticsReports;
  if (typeof window.loadAnalyticsSources === 'function') window.TrueID.loadAnalyticsSources = window.loadAnalyticsSources;
  if (typeof window.loadAnalyticsTab === 'function') window.TrueID.loadAnalyticsTab = window.loadAnalyticsTab;
  if (typeof window.loadAnalyticsTrends === 'function') window.TrueID.loadAnalyticsTrends = window.loadAnalyticsTrends;
  if (typeof window.openAnalyticsReport === 'function') window.TrueID.openAnalyticsReport = window.openAnalyticsReport;
  if (typeof window.renderBarChart === 'function') window.TrueID.renderBarChart = window.renderBarChart;
  if (typeof window.renderDonutChart === 'function') window.TrueID.renderDonutChart = window.renderDonutChart;
})();
