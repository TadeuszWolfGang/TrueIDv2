var currentUser = null;
      var activeTab = 'mappings';
      var notificationEditingId = null;
      var evtSource = null;
      var sseConnected = false;
      var matrixRainTimer = null;
      var matrixRainEnabled = localStorage.getItem('trueid_matrix_rain') !== 'false';
      var tabLoaded = {
        mappings: false, search: false, conflicts: false, alerts: false, analytics: false, map: false, status: false,
        subnets: false, switches: false, fingerprints: false, dns: false,
        firewall: false, siem: false, ldap: false, notifications: false, sycope: false, audit: false
      };
      var tabRefreshTimers = { mappings: null, conflicts: null, alerts: null, analytics: null, map: null, status: null, audit: null };

      var mappingsCurrentPage = 1;
      var mappingsPerPage = 50;
      var searchCurrentPage = 1;
      var searchPerPage = 50;
      var conflictsCurrentPage = 1;
      var alertHistoryCurrentPage = 1;
      var editingRuleId = null;
      var auditCurrentPage = 1;
      var firewallEditingId = null;
      var firewallTargets = [];
      var firewallHistoryOpen = {};
      var siemEditingId = null;
      var siemTargets = [];
      var subnets = [];
      var subnetCurrentPage = 1;
      var subnetPageSize = 50;
      var subnetMappingOpen = {};
      var subnetCounts = {};
      var switches = [];
      var switchesCurrentPage = 1;
      var switchesPageSize = 50;
      var switchPortOpen = {};
      var switchEditingId = null;
      var fingerprints = [];
      var fpCurrentPage = 1;
      var fpPageSize = 50;
      var fpObsCurrentPage = 1;
      var dnsCurrentPage = 1;
      window.TrueID = window.TrueID || {};
      window.TrueID.currentUser = currentUser;
      window.TrueID.activeTab = activeTab;
      window.TrueID.csrfToken = null;
      window.TrueID.sseConnected = sseConnected;
      window.TrueID.evtSource = evtSource;
      window.TrueID.pollingTimers = tabRefreshTimers;

      function themeColor(name) {
        return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
      }

      function updateMatrixToggleUi() {
        var btn = document.getElementById('matrix-toggle');
        if (!btn) return;
        btn.textContent = matrixRainEnabled ? '◈' : '◇';
        btn.style.color = matrixRainEnabled ? 'var(--green-bright)' : 'var(--text-secondary)';
      }

      function stopMatrixRain() {
        if (matrixRainTimer) {
          clearInterval(matrixRainTimer);
          matrixRainTimer = null;
        }
        var canvas = document.getElementById('matrix-bg');
        if (canvas) canvas.style.display = 'none';
      }

      function startMatrixRain() {
        var canvas = document.getElementById('matrix-bg');
        if (!canvas) return;
        canvas.style.display = '';
        var ctx = canvas.getContext('2d');
        if (!ctx) return;
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
          ctx.fillStyle = themeColor('--green-bright');
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
        matrixRainTimer = setInterval(draw, 50);
      }

      function toggleMatrixRain() {
        matrixRainEnabled = !matrixRainEnabled;
        localStorage.setItem('trueid_matrix_rain', matrixRainEnabled ? 'true' : 'false');
        if (matrixRainEnabled) {
          startMatrixRain();
        } else {
          stopMatrixRain();
        }
        updateMatrixToggleUi();
      }

      (function initMatrixRain() {
        updateMatrixToggleUi();
        if (matrixRainEnabled) {
          startMatrixRain();
        } else {
          stopMatrixRain();
        }
      })();


      function getRealtimePollInterval(tabName) {
        if ((tabName === 'mappings' || tabName === 'conflicts' || tabName === 'alerts') && sseConnected) {
          return 120000;
        }
        return 30000;
      }

      function refreshRealtimeTabPolling() {
        if (activeTab === 'mappings' || activeTab === 'conflicts' || activeTab === 'alerts') {
          switchTab(activeTab);
        }
      }

      function updateConnectionStatus(connected) {
        var el = document.getElementById('connection-status');
        if (!el) return;
        if (connected) {
          el.innerHTML = '<span class="dot online"></span> Live';
        } else {
          el.innerHTML = '<span class="dot offline"></span> Polling';
        }
      }

      function showLiveIndicator(type, message) {
        var host = document.getElementById('live-indicator');
        if (!host) return;
        var color = 'var(--status-ok)';
        if (type === 'alert') color = 'var(--status-error)';
        if (type === 'conflict') color = 'var(--status-warn)';
        if (type === 'firewall') color = 'var(--status-info)';
        var toast = document.createElement('div');
        toast.className = 'live-toast';
        toast.style.cssText = 'background:var(--bg-panel);border:1px solid ' + color +
          ';border-radius:6px;padding:8px 12px;margin-top:8px;font-size:12px;color:' +
          color + ';max-width:320px;text-shadow:var(--text-glow);';
        toast.textContent = '⚡ ' + message;
        host.appendChild(toast);
        setTimeout(function () { toast.remove(); }, 5000);
      }

      function handleMappingUpdate(data) {
        showLiveIndicator('mapping', (data.ip || '-') + ' -> ' + (data.user || '-'));
        if (activeTab === 'mappings') loadMappings(mappingsCurrentPage);
      }

      function handleConflictEvent(data) {
        showLiveIndicator('conflict', (data.severity || 'warning') + ': ' + (data.ip || 'unknown'));
        if (activeTab === 'conflicts') {
          loadConflictsStats();
          loadConflicts(conflictsCurrentPage);
        }
      }

      function handleAlertEvent(data) {
        showLiveIndicator('alert', (data.severity || 'warning') + ': ' + (data.rule_name || 'rule'));
        if (activeTab === 'alerts') {
          loadAlertStats();
          loadAlertHistory(alertHistoryCurrentPage);
        }
      }

      function handleFirewallEvent(data) {
        var label = data.target_name || 'firewall';
        var status = data.success ? 'ok' : 'error';
        showLiveIndicator('firewall', label + ' push ' + status);
      }

      function connectSSE() {
        if (evtSource) evtSource.close();
        evtSource = new EventSource('/api/v2/events/stream');

        evtSource.onopen = function () {
          sseConnected = true;
          updateConnectionStatus(true);
          refreshRealtimeTabPolling();
        };
        evtSource.addEventListener('mapping', function (e) {
          handleMappingUpdate(JSON.parse(e.data || '{}'));
        });
        evtSource.addEventListener('conflict', function (e) {
          handleConflictEvent(JSON.parse(e.data || '{}'));
        });
        evtSource.addEventListener('alert', function (e) {
          handleAlertEvent(JSON.parse(e.data || '{}'));
        });
        evtSource.addEventListener('firewall', function (e) {
          handleFirewallEvent(JSON.parse(e.data || '{}'));
        });
        evtSource.onerror = function () {
          if (evtSource) evtSource.close();
          evtSource = null;
          sseConnected = false;
          updateConnectionStatus(false);
          refreshRealtimeTabPolling();
          setTimeout(connectSSE, 5000);
        };
      }

      async function initAuth() {
        try {
          var resp = await fetch('/api/auth/me', { credentials: 'include' });
          if (resp.status === 401 || !resp.ok) {
            window.location = '/login.html';
            return;
          }
          var meData = await resp.json();
          currentUser = meData.user;
          currentUser.force_password_change = meData.force_password_change;
          currentUser.active_sessions_count = meData.active_sessions_count;

          document.getElementById('user-info').textContent =
            'Logged in as ' + currentUser.username + ' (' + currentUser.role + ')';
          document.getElementById('user-bar').style.display = 'flex';
          updateConnectionStatus(false);
          applyRoleVisibility(currentUser.role);
          switchTab('mappings');
          connectSSE();
        } catch (e) {
          window.location = '/login.html';
        }
      }

      function applyRoleVisibility(role) {
        var isAdmin = role === 'Admin';
        var isOperatorOrAdmin = role === 'Operator' || role === 'Admin';
        document.getElementById('tab-btn-status').style.display = isAdmin ? '' : 'none';
        document.getElementById('tab-btn-firewall').style.display = isOperatorOrAdmin ? '' : 'none';
        document.getElementById('tab-btn-siem').style.display = isOperatorOrAdmin ? '' : 'none';
        document.getElementById('tab-btn-ldap').style.display = isOperatorOrAdmin ? '' : 'none';
        document.getElementById('tab-btn-notifications').style.display = isAdmin ? '' : 'none';
        document.getElementById('tab-btn-sycope').style.display = isAdmin ? '' : 'none';
        document.getElementById('tab-btn-audit').style.display = isAdmin ? '' : 'none';
        document.querySelectorAll('.role-operator').forEach(function (el) {
          el.style.display = isOperatorOrAdmin ? '' : 'none';
        });
        document.querySelectorAll('.role-admin').forEach(function (el) {
          el.style.display = isAdmin ? '' : 'none';
        });
        document.getElementById('alerts-rules-section').style.display = isAdmin ? '' : 'none';
      }

      async function doLogout() {
        if (evtSource) {
          evtSource.close();
          evtSource = null;
        }
        sseConnected = false;
        updateConnectionStatus(false);
        try {
          await fetch('/api/auth/logout', {
            method: 'POST',
            headers: mutHeaders(),
            credentials: 'include'
          });
        } catch (e) {}
        window.location = '/login.html';
      }


      var refreshing = false;
      async function refreshToken() {
        if (refreshing || document.visibilityState === 'hidden') return;
        refreshing = true;
        try {
          var resp = await fetch('/api/auth/refresh', {
            method: 'POST',
            headers: { 'X-CSRF-Token': getCsrfToken() },
            credentials: 'include'
          });
          if (!resp.ok) window.location = '/login.html';
        } finally {
          refreshing = false;
        }
      }
      setInterval(refreshToken, 10 * 60 * 1000);

      function clearTabTimers() {
        ['mappings', 'conflicts', 'alerts', 'analytics', 'map', 'status', 'audit'].forEach(function (k) {
          if (tabRefreshTimers[k]) {
            clearInterval(tabRefreshTimers[k]);
            tabRefreshTimers[k] = null;
          }
        });
      }

      function switchTab(name) {
        activeTab = name;
        ['mappings', 'search', 'conflicts', 'alerts', 'analytics', 'map', 'subnets', 'switches', 'fingerprints', 'dns', 'status', 'firewall', 'siem', 'ldap', 'notifications', 'sycope', 'audit'].forEach(function (n) {
          var panel = document.getElementById('tab-' + n);
          if (panel) panel.style.display = n === name ? 'block' : 'none';
        });
        document.querySelectorAll('#tabs .tab').forEach(function (btn) {
          btn.classList.remove('active');
        });
        var activeBtn = document.getElementById('tab-btn-' + name);
        if (activeBtn) activeBtn.classList.add('active');

        if (name === 'mappings') {
          if (!tabLoaded.mappings) {
            tabLoaded.mappings = true;
            loadMappingsStats();
            loadMappings(1);
          }
          clearTabTimers();
          tabRefreshTimers.mappings = setInterval(function () {
            if (activeTab === 'mappings') loadMappings(mappingsCurrentPage);
          }, getRealtimePollInterval('mappings'));
        } else if (name === 'search') {
          if (!tabLoaded.search) tabLoaded.search = true;
          clearTabTimers();
        } else if (name === 'conflicts') {
          if (!tabLoaded.conflicts) {
            tabLoaded.conflicts = true;
            loadConflictsStats();
            loadConflicts(1);
          }
          clearTabTimers();
          tabRefreshTimers.conflicts = setInterval(function () {
            if (activeTab === 'conflicts') {
              loadConflictsStats();
              loadConflicts(conflictsCurrentPage);
            }
          }, getRealtimePollInterval('conflicts'));
        } else if (name === 'alerts') {
          if (!tabLoaded.alerts) {
            tabLoaded.alerts = true;
            loadAlertStats();
            loadAlertHistory(1);
            if (currentUser && currentUser.role === 'Admin') loadAlertRules();
          }
          clearTabTimers();
          tabRefreshTimers.alerts = setInterval(function () {
            if (activeTab === 'alerts') {
              loadAlertStats();
              loadAlertHistory(alertHistoryCurrentPage);
              if (currentUser && currentUser.role === 'Admin') loadAlertRules();
            }
          }, getRealtimePollInterval('alerts'));
        } else if (name === 'analytics') {
          if (!tabLoaded.analytics) {
            tabLoaded.analytics = true;
            loadAnalyticsTab();
          } else {
            loadAnalyticsTab();
          }
          clearTabTimers();
          tabRefreshTimers.analytics = setInterval(function () {
            if (activeTab === 'analytics') loadAnalyticsTab();
          }, 60000);
        } else if (name === 'map') {
          if (!tabLoaded.map) {
            tabLoaded.map = true;
            loadMapTab();
          } else {
            loadMapTab();
          }
          clearTabTimers();
          tabRefreshTimers.map = setInterval(function () {
            if (activeTab === 'map') loadMapTab();
          }, 60000);
        } else if (name === 'subnets') {
          if (!tabLoaded.subnets) tabLoaded.subnets = true;
          clearTabTimers();
          loadSubnetsTab();
        } else if (name === 'switches') {
          if (!tabLoaded.switches) tabLoaded.switches = true;
          clearTabTimers();
          loadSwitchesTab();
        } else if (name === 'fingerprints') {
          if (!tabLoaded.fingerprints) tabLoaded.fingerprints = true;
          clearTabTimers();
          loadFingerprintsTab();
        } else if (name === 'dns') {
          if (!tabLoaded.dns) tabLoaded.dns = true;
          clearTabTimers();
          loadDnsTab();
        } else if (name === 'status') {
          if (!tabLoaded.status) {
            tabLoaded.status = true;
            loadSystemStatus();
          } else {
            loadSystemStatus();
          }
          clearTabTimers();
          tabRefreshTimers.status = setInterval(function () {
            if (activeTab === 'status') loadSystemStatus();
          }, 15000);
        } else if (name === 'firewall') {
          if (!tabLoaded.firewall) tabLoaded.firewall = true;
          clearTabTimers();
          loadFirewallTab();
        } else if (name === 'siem') {
          if (!tabLoaded.siem) tabLoaded.siem = true;
          clearTabTimers();
          loadSiemTab();
        } else if (name === 'ldap') {
          if (!tabLoaded.ldap) tabLoaded.ldap = true;
          clearTabTimers();
          loadLdapTab();
        } else if (name === 'notifications') {
          if (!tabLoaded.notifications) tabLoaded.notifications = true;
          clearTabTimers();
          loadNotificationsTab();
        } else if (name === 'sycope') {
          clearTabTimers();
          loadSycopeConfig();
        } else if (name === 'audit') {
          clearTabTimers();
          loadAuditStats();
          loadAuditLogs(auditCurrentPage);
          tabRefreshTimers.audit = setInterval(function () {
            if (activeTab === 'audit') loadAuditLogs(auditCurrentPage);
          }, 30000);
        } else {
          clearTabTimers();
        }
      }


      window.TrueID.initAuth = initAuth;
      window.TrueID.switchTab = switchTab;
      window.TrueID.connectSSE = connectSSE;
      window.TrueID.doLogout = doLogout;
      window.TrueID.toggleMatrixRain = toggleMatrixRain;
      window.TrueID.getState = function () {
        return {
          currentUser: currentUser,
          activeTab: activeTab,
          sseConnected: sseConnected,
          evtSource: evtSource,
          pollingTimers: tabRefreshTimers,
        };
      };

      initAuth();
