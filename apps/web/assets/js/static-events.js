'use strict';

(function bindStaticEvents() {
  function bind(id, type, listener) {
    var element = document.getElementById(id);
    if (!element) {
      throw new Error('Missing static event target: ' + id);
    }
    element.addEventListener(type, listener);
  }

  bind('tab-btn-mappings', 'click', function (event) {
    switchTab('mappings');
  });

  bind('tab-btn-search', 'click', function (event) {
    switchTab('search');
  });

  bind('tab-btn-conflicts', 'click', function (event) {
    switchTab('conflicts');
  });

  bind('tab-btn-alerts', 'click', function (event) {
    switchTab('alerts');
  });

  bind('tab-btn-analytics', 'click', function (event) {
    switchTab('analytics');
  });

  bind('tab-btn-map', 'click', function (event) {
    switchTab('map');
  });

  bind('tab-btn-subnets', 'click', function (event) {
    switchTab('subnets');
  });

  bind('tab-btn-switches', 'click', function (event) {
    switchTab('switches');
  });

  bind('tab-btn-fingerprints', 'click', function (event) {
    switchTab('fingerprints');
  });

  bind('tab-btn-dns', 'click', function (event) {
    switchTab('dns');
  });

  bind('tab-btn-firewall', 'click', function (event) {
    switchTab('firewall');
  });

  bind('tab-btn-siem', 'click', function (event) {
    switchTab('siem');
  });

  bind('tab-btn-ldap', 'click', function (event) {
    switchTab('ldap');
  });

  bind('tab-btn-notifications', 'click', function (event) {
    switchTab('notifications');
  });

  bind('tab-btn-sycope', 'click', function (event) {
    switchTab('sycope');
  });

  bind('tab-btn-audit', 'click', function (event) {
    switchTab('audit');
  });

  bind('tab-btn-status', 'click', function (event) {
    switchTab('status');
  });

  bind('matrix-toggle', 'click', function (event) {
    toggleMatrixRain();
  });

  bind('security-btn', 'click', function (event) {
    openSecurityModal();
  });

  bind('logout-btn', 'click', function (event) {
    doLogout();
  });

  bind('mappings-search', 'keydown', function (event) {
    if(event.key==='Enter')loadMappings(1);
  });

  bind('static-event-1', 'click', function (event) {
    loadMappings(1);
  });

  bind('static-event-2', 'click', function (event) {
    loadMappings(mappingsCurrentPage);
  });

  bind('static-event-3', 'click', function (event) {
    exportMappings('csv');
  });

  bind('static-event-4', 'click', function (event) {
    exportMappings('json');
  });

  bind('search-q', 'keydown', function (event) {
    if(event.key==='Enter')doSearch(1);
  });

  bind('static-event-5', 'click', function (event) {
    doSearch(1);
  });

  bind('static-event-6', 'click', function (event) {
    exportEvents('csv');
  });

  bind('static-event-7', 'click', function (event) {
    exportEvents('json');
  });

  bind('static-event-8', 'click', function (event) {
    loadConflicts(1);
  });

  bind('static-event-9', 'click', function (event) {
    showAddRuleForm();
  });

  bind('rule-type', 'change', function (event) {
    updateAlertRuleConditionalFields();
  });

  bind('alert-rule-save-btn', 'click', function (event) {
    saveAlertRule();
  });

  bind('static-event-10', 'click', function (event) {
    hideRuleForm();
  });

  bind('static-event-11', 'click', function (event) {
    loadAlertHistory(1);
  });

  bind('static-event-12', 'click', function (event) {
    generateAnalyticsReport();
  });

  bind('static-event-13', 'click', function (event) {
    loadAnalyticsReports();
  });

  bind('static-event-14', 'click', function (event) {
    saveReportSchedule();
  });

  bind('static-event-15', 'click', function (event) {
    loadReportSchedules();
  });

  bind('static-event-16', 'click', function (event) {
    showSubnetForm();
  });

  bind('static-event-17', 'click', function (event) {
    loadSubnets();
  });

  bind('static-event-18', 'click', function (event) {
    saveSubnet();
  });

  bind('static-event-19', 'click', function (event) {
    hideSubnetForm();
  });

  bind('static-event-20', 'click', function (event) {
    loadDiscoveredSubnets();
  });

  bind('static-event-21', 'click', function (event) {
    showSwitchForm();
  });

  bind('static-event-22', 'click', function (event) {
    loadSwitches();
  });

  bind('static-event-23', 'click', function (event) {
    saveSwitch();
  });

  bind('static-event-24', 'click', function (event) {
    hideSwitchForm();
  });

  bind('static-event-25', 'click', function (event) {
    showFingerprintForm();
  });

  bind('static-event-26', 'click', function (event) {
    runFingerprintBackfill();
  });

  bind('static-event-27', 'click', function (event) {
    loadFingerprintsTab();
  });

  bind('static-event-28', 'click', function (event) {
    saveFingerprint();
  });

  bind('static-event-29', 'click', function (event) {
    hideFingerprintForm();
  });

  bind('dns-lookup-ip', 'keydown', function (event) {
    if(event.key==='Enter')dnsLookupIp();
  });

  bind('static-event-30', 'click', function (event) {
    dnsLookupIp();
  });

  bind('static-event-31', 'click', function (event) {
    flushDnsCache();
  });

  bind('static-event-32', 'click', function (event) {
    loadDnsTab();
  });

  bind('static-event-33', 'click', function (event) {
    runRetentionNow();
  });

  bind('static-event-34', 'click', function (event) {
    loadRetentionSection();
  });

  bind('static-event-35', 'click', function (event) {
    saveAdminSecurityPolicy();
  });

  bind('static-event-36', 'click', function (event) {
    loadAdminSecuritySection();
  });

  bind('static-event-37', 'click', function (event) {
    testOidcDiscovery();
  });

  bind('static-event-38', 'click', function (event) {
    saveOidcConfig();
  });

  bind('static-event-39', 'click', function (event) {
    createApiKey();
  });

  bind('static-event-40', 'click', function (event) {
    loadApiKeysSection();
  });

  bind('static-event-41', 'click', function (event) {
    openAddUserModal();
  });

  bind('static-event-42', 'click', function (event) {
    loadUsersSection();
  });

  bind('static-event-43', 'click', function (event) {
    quickAddTag();
  });

  bind('static-event-44', 'click', function (event) {
    showFirewallForm();
  });

  bind('static-event-45', 'click', function (event) {
    loadFirewallTargets();
  });

  bind('fw-type', 'change', function (event) {
    toggleFirewallUsername();
  });

  bind('static-event-46', 'click', function (event) {
    saveFirewallTarget();
  });

  bind('static-event-47', 'click', function (event) {
    hideFirewallForm();
  });

  bind('static-event-48', 'click', function (event) {
    showSiemForm();
  });

  bind('static-event-49', 'click', function (event) {
    loadSiemTargets();
  });

  bind('static-event-50', 'click', function (event) {
    saveSiemTarget();
  });

  bind('static-event-51', 'click', function (event) {
    hideSiemForm();
  });

  bind('ldap-enabled', 'change', function (event) {
    saveLdapField('enabled', this.checked, this);
  });

  bind('ldap-url', 'change', function (event) {
    saveLdapField('ldap_url', this.value, this);
  });

  bind('ldap-bind-dn', 'change', function (event) {
    saveLdapField('bind_dn', this.value, this);
  });

  bind('static-event-52', 'click', function (event) {
    saveLdapPassword();
  });

  bind('ldap-base-dn', 'change', function (event) {
    saveLdapField('base_dn', this.value, this);
  });

  bind('ldap-filter', 'change', function (event) {
    saveLdapField('search_filter', this.value, this);
  });

  bind('ldap-interval', 'change', function (event) {
    saveLdapField('sync_interval_secs', parseInt(this.value || '300', 10), this);
  });

  bind('static-event-53', 'click', function (event) {
    forceLdapSync();
  });

  bind('static-event-54', 'click', function (event) {
    loadLdapTab();
  });

  bind('ldap-user-query', 'keydown', function (event) {
    if(event.key==='Enter')lookupLdapUserGroups();
  });

  bind('static-event-55', 'click', function (event) {
    lookupLdapUserGroups();
  });

  bind('static-event-56', 'click', function (event) {
    showNotificationForm();
  });

  bind('static-event-57', 'click', function (event) {
    loadNotificationsTab();
  });

  bind('notif-type', 'change', function (event) {
    renderNotificationConfigForm();
  });

  bind('static-event-58', 'click', function (event) {
    saveNotificationChannel();
  });

  bind('static-event-59', 'click', function (event) {
    hideNotificationForm();
  });

  bind('sycope-enabled', 'change', function (event) {
    saveSycopeField('enabled', this.checked, this);
  });

  bind('sycope-host', 'change', function (event) {
    saveSycopeField('sycope_host', this.value, this);
  });

  bind('sycope-login', 'change', function (event) {
    saveSycopeField('sycope_login', this.value, this);
  });

  bind('static-event-60', 'click', function (event) {
    saveSycopePassword();
  });

  bind('test-btn', 'click', function (event) {
    testSycopeConnection();
  });

  bind('sycope-lookup', 'change', function (event) {
    saveSycopeField('lookup_name', this.value, this);
  });

  bind('sycope-interval', 'change', function (event) {
    saveSycopeField('sync_interval_seconds', parseInt(this.value), this);
  });

  bind('sycope-evt-idx', 'change', function (event) {
    saveSycopeField('enable_event_index', this.checked, this);
  });

  bind('sycope-idx-name', 'change', function (event) {
    saveSycopeField('index_name', this.value, this);
  });

  bind('static-event-61', 'click', function (event) {
    loadAuditLogs(1);
  });

  bind('static-event-62', 'click', function (event) {
    closeTimeline();
  });

  bind('static-event-63', 'click', function (event) {
    closeAnalyticsReportModal();
  });

  bind('static-event-64', 'click', function (event) {
    closeAddUserModal();
  });

  bind('static-event-65', 'click', function (event) {
    createUserFromModal();
  });

  bind('static-event-66', 'click', function (event) {
    closeAddUserModal();
  });

  bind('static-event-67', 'click', function (event) {
    closeSecurityModal();
  });

  bind('static-event-68', 'click', function (event) {
    verifyTotpSetup();
  });
})();
