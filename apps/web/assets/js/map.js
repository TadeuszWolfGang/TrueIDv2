(function () {
  var mapState = {
    topology: null,
    pathBySubnet: {},
    recentFlowKeys: {},
  };

  /**
   * Creates an SVG element with attributes.
   * @param {string} tag SVG tag name.
   * @param {Object} attrs Attribute map.
   * @returns {SVGElement} Created node.
   */
  function createSvgElement(tag, attrs) {
    var el = document.createElementNS('http://www.w3.org/2000/svg', tag);
    Object.keys(attrs || {}).forEach(function (k) {
      el.setAttribute(k, String(attrs[k]));
    });
    return el;
  }

  /**
   * Escapes value for use in DOM id.
   * @param {string} value Raw value.
   * @returns {string} Safe id fragment.
   */
  function safeId(value) {
    return String(value || '')
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 64);
  }

  /**
   * Returns stroke color by conflict severity.
   * @param {number} conflicts Unresolved conflicts count.
   * @returns {string} CSS color var.
   */
  function subnetStroke(conflicts) {
    if (conflicts > 3) return 'var(--status-error)';
    if (conflicts > 0) return 'var(--status-warn)';
    return 'var(--green-dim)';
  }

  /**
   * Shows subnet hover tooltip.
   * @param {MouseEvent} evt Pointer event.
   * @param {Object} subnet Subnet payload.
   * @returns {void}
   */
  function showMapTooltip(evt, subnet) {
    var tip = document.getElementById('map-tooltip');
    if (!tip) return;
    var topUsers = (subnet.top_users || []).length ? subnet.top_users.join(', ') : '-';
    tip.textContent =
      subnet.name + ' (' + subnet.cidr + ')\n' +
      subnet.active_ips + ' active IPs · ' +
      subnet.total_mappings + ' mappings · ' +
      subnet.conflict_count + ' conflicts\n' +
      'Top users: ' + topUsers;
    tip.style.display = 'block';
    tip.style.left = (evt.clientX + 14) + 'px';
    tip.style.top = (evt.clientY + 14) + 'px';
  }

  /**
   * Hides map tooltip.
   * @returns {void}
   */
  function hideMapTooltip() {
    var tip = document.getElementById('map-tooltip');
    if (!tip) return;
    tip.style.display = 'none';
  }

  /**
   * Renders one subnet node rectangle and labels.
   * @param {SVGElement} svg SVG root.
   * @param {Object} subnet Subnet payload.
   * @param {number} x Left.
   * @param {number} y Top.
   * @param {number} w Width.
   * @param {number} h Height.
   * @param {boolean} discovered Whether discovered subnet node.
   * @returns {void}
   */
  function renderSubnetNode(svg, subnet, x, y, w, h, discovered) {
    var rect = createSvgElement('rect', {
      x: x,
      y: y,
      width: w,
      height: h,
      rx: 4,
      fill: discovered ? 'rgba(0,255,65,0.04)' : 'var(--bg-panel)',
      stroke: discovered ? 'var(--green-mid)' : subnetStroke(subnet.conflict_count || 0),
      'stroke-width': discovered ? 1 : 1.5,
      'stroke-dasharray': discovered ? '5 3' : '',
      class: 'map-node-hover',
    });
    svg.appendChild(rect);
    if (!discovered) {
      rect.addEventListener('mousemove', function (evt) {
        showMapTooltip(evt, subnet);
      });
      rect.addEventListener('mouseleave', hideMapTooltip);
    }

    var title = createSvgElement('text', {
      x: x + w / 2,
      y: y + 18,
      fill: 'var(--green-bright)',
      'font-size': '12',
      'text-anchor': 'middle',
      'font-family': 'inherit',
    });
    title.textContent = subnet.name || subnet.cidr;
    svg.appendChild(title);

    var count = createSvgElement('text', {
      x: x + w / 2,
      y: y + 34,
      fill: 'var(--text-secondary)',
      'font-size': '10',
      'text-anchor': 'middle',
      'font-family': 'inherit',
    });
    count.textContent = (subnet.active_ips || subnet.ip_count || 0) + ' IPs';
    svg.appendChild(count);

    var cidr = createSvgElement('text', {
      x: x + w / 2,
      y: y + 48,
      fill: 'var(--text-secondary)',
      'font-size': '10',
      'text-anchor': 'middle',
      'font-family': 'inherit',
    });
    cidr.textContent = subnet.cidr || '';
    svg.appendChild(cidr);
  }

  /**
   * Renders adapter icon node.
   * @param {SVGElement} svg SVG root.
   * @param {Object} adapter Adapter payload.
   * @param {number} x Left.
   * @param {number} y Top.
   * @returns {void}
   */
  function renderAdapterNode(svg, adapter, x, y) {
    var group = createSvgElement('g', { class: 'map-node-hover' });
    var box = createSvgElement('rect', {
      x: x,
      y: y,
      width: 140,
      height: 54,
      rx: 5,
      fill: 'var(--bg-panel)',
      stroke: 'var(--green-dim)',
      'stroke-width': 1.2,
    });
    group.appendChild(box);

    var icon = createSvgElement('path', {
      d: 'M ' + (x + 10) + ' ' + (y + 28) + ' h 18 M ' + (x + 10) + ' ' + (y + 22) + ' h 12 M ' + (x + 10) + ' ' + (y + 34) + ' h 12',
      stroke: 'var(--green-bright)',
      'stroke-width': 1.4,
      fill: 'none',
      'stroke-linecap': 'round',
    });
    group.appendChild(icon);

    var label = createSvgElement('text', {
      x: x + 70,
      y: y + 22,
      fill: 'var(--green-bright)',
      'font-size': '11',
      'text-anchor': 'middle',
      'font-family': 'inherit',
    });
    label.textContent = adapter.name;
    group.appendChild(label);

    var sub = createSvgElement('text', {
      x: x + 70,
      y: y + 38,
      fill: 'var(--text-secondary)',
      'font-size': '10',
      'text-anchor': 'middle',
      'font-family': 'inherit',
    });
    sub.textContent = (adapter.status || 'unknown') + ' · ' + (adapter.event_count || 0);
    group.appendChild(sub);
    svg.appendChild(group);
  }

  /**
   * Renders one integration node rectangle.
   * @param {SVGElement} svg SVG root.
   * @param {string} title Node title.
   * @param {string} value Node value.
   * @param {number} x Left.
   * @param {number} y Top.
   * @returns {void}
   */
  function renderIntegrationNode(svg, title, value, x, y) {
    svg.appendChild(createSvgElement('rect', {
      x: x,
      y: y,
      width: 150,
      height: 48,
      rx: 5,
      fill: 'var(--bg-panel)',
      stroke: 'var(--green-dim)',
      'stroke-width': 1.2,
      class: 'map-node-hover',
    }));
    var titleEl = createSvgElement('text', {
      x: x + 75,
      y: y + 19,
      fill: 'var(--green-bright)',
      'font-size': '11',
      'text-anchor': 'middle',
      'font-family': 'inherit',
    });
    titleEl.textContent = title;
    svg.appendChild(titleEl);
    var valEl = createSvgElement('text', {
      x: x + 75,
      y: y + 35,
      fill: 'var(--text-secondary)',
      'font-size': '10',
      'text-anchor': 'middle',
      'font-family': 'inherit',
    });
    valEl.textContent = value;
    svg.appendChild(valEl);
  }

  /**
   * Draws a curved path between two points.
   * @param {SVGElement} svg SVG root.
   * @param {string} id Path id.
   * @param {number} x1 Source x.
   * @param {number} y1 Source y.
   * @param {number} x2 Target x.
   * @param {number} y2 Target y.
   * @param {number} width Stroke width.
   * @returns {void}
   */
  function drawPath(svg, id, x1, y1, x2, y2, width) {
    var midX = (x1 + x2) / 2;
    svg.appendChild(createSvgElement('path', {
      id: id,
      d: 'M ' + x1 + ' ' + y1 + ' C ' + midX + ' ' + y1 + ', ' + midX + ' ' + y2 + ', ' + x2 + ' ' + y2,
      fill: 'none',
      stroke: 'var(--green-dim)',
      'stroke-width': Math.max(1, Math.min(4, width)),
      class: 'map-flow-line',
      opacity: 0.85,
    }));
  }

  /**
   * Animates a flow dot along given path.
   * @param {SVGElement} svg SVG root.
   * @param {string} pathId Path id.
   * @returns {void}
   */
  function animateFlow(svg, pathId) {
    var path = document.getElementById(pathId);
    if (!svg || !path) return;
    var dot = createSvgElement('circle', { r: 3, fill: 'var(--green-bright)', filter: 'url(#glow)' });
    var motion = createSvgElement('animateMotion', { dur: '1.4s', repeatCount: '1' });
    var mpath = createSvgElement('mpath', {});
    mpath.setAttributeNS('http://www.w3.org/1999/xlink', 'xlink:href', '#' + pathId);
    motion.appendChild(mpath);
    dot.appendChild(motion);
    svg.appendChild(dot);
    setTimeout(function () { dot.remove(); }, 1500);
  }

  /**
   * Promotes discovered subnet to managed subnet.
   * @param {number} discoveredId Discovered subnet id.
   * @param {string} cidr Subnet CIDR.
   * @returns {Promise<void>}
   */
  async function promoteDiscovered(discoveredId, cidr) {
    try {
      var name = 'Auto ' + cidr;
      await authPost('/api/v2/subnets/promote', {
        discovered_id: discoveredId,
        name: name,
        vlan_id: null,
      });
      showFlash('Promoted ' + cidr, true);
      await loadMapTopology();
    } catch (e) {
      showFlash('Promote failed: ' + e.message, false);
    }
  }

  /**
   * Renders topology SVG from backend payload.
   * @param {Object} data Topology response.
   * @returns {void}
   */
  function renderTopology(data) {
    var svg = document.getElementById('network-svg');
    if (!svg) return;
    svg.innerHTML = '';
    svg.setAttribute('viewBox', '0 0 1200 600');
    mapState.pathBySubnet = {};

    var defs = createSvgElement('defs', {});
    var filter = createSvgElement('filter', { id: 'glow' });
    filter.appendChild(createSvgElement('feGaussianBlur', { stdDeviation: 2, result: 'coloredBlur' }));
    var merge = createSvgElement('feMerge', {});
    merge.appendChild(createSvgElement('feMergeNode', { in: 'coloredBlur' }));
    merge.appendChild(createSvgElement('feMergeNode', { in: 'SourceGraphic' }));
    filter.appendChild(merge);
    defs.appendChild(filter);
    svg.appendChild(defs);

    var statIps = document.getElementById('map-stat-ips');
    var statUsers = document.getElementById('map-stat-users');
    var statConflicts = document.getElementById('map-stat-conflicts');
    if (statIps) statIps.textContent = 'Total IPs: ' + (data.stats.total_ips || 0);
    if (statUsers) statUsers.textContent = 'Total Users: ' + (data.stats.total_users || 0);
    if (statConflicts) statConflicts.textContent = 'Active Conflicts: ' + (data.stats.active_conflicts || 0);

    var subnets = data.subnets || [];
    var discovered = data.discovered_subnets || [];
    var adapters = data.adapters || [];
    var integrations = data.integrations || {};

    var leftX = 50;
    var centerX = 520;
    var rightX = 980;
    var subnetGap = 74;
    var subnetW = 260;
    var subnetH = 56;

    subnets.forEach(function (s, idx) {
      renderSubnetNode(svg, s, leftX, 50 + idx * subnetGap, subnetW, subnetH, false);
    });

    var discoveredBaseY = 60 + subnets.length * subnetGap;
    discovered.forEach(function (s, idx) {
      var y = discoveredBaseY + idx * 64;
      renderSubnetNode(svg, s, leftX, y, subnetW, 52, true);
      var canPromote = window.TrueID && window.TrueID.getState && window.TrueID.getState().currentUser &&
        (window.TrueID.getState().currentUser.role === 'Admin' || window.TrueID.getState().currentUser.role === 'Operator');
      if (canPromote) {
        var btn = createSvgElement('text', {
          x: leftX + subnetW - 44,
          y: y + 18,
          fill: 'var(--green-bright)',
          'font-size': '10',
          'font-family': 'inherit',
          style: 'cursor:pointer;text-decoration:underline;',
        });
        btn.textContent = 'Promote';
        btn.addEventListener('click', function () {
          promoteDiscovered(s.id, s.cidr);
        });
        svg.appendChild(btn);
      }
    });

    adapters.forEach(function (a, idx) {
      renderAdapterNode(svg, a, centerX, 70 + idx * 76);
    });

    renderIntegrationNode(svg, 'Firewall', (integrations.firewall_targets || 0) + ' targets', rightX, 120);
    renderIntegrationNode(svg, 'SIEM', (integrations.siem_targets || 0) + ' targets', rightX, 210);
    renderIntegrationNode(svg, 'LDAP', integrations.ldap_configured ? 'configured' : 'disabled', rightX, 300);

    adapters.forEach(function (a, ai) {
      var lineW = 1 + ((a.event_count || 0) / 250);
      subnets.forEach(function (s, si) {
        var pathId = 'map-path-' + safeId(a.type || a.name) + '-' + safeId(s.name);
        drawPath(svg, pathId, centerX, 97 + ai * 76, leftX + subnetW, 78 + si * subnetGap, lineW);
        if (!mapState.pathBySubnet[s.name]) mapState.pathBySubnet[s.name] = pathId;
      });
    });
    subnets.forEach(function (s, si) {
      ['fw', 'siem', 'ldap'].forEach(function (k, idx) {
        drawPath(
          svg,
          'map-path-subnet-' + safeId(s.name) + '-' + k,
          leftX + subnetW,
          78 + si * subnetGap,
          rightX,
          144 + idx * 90,
          1.2
        );
      });
    });
  }

  /**
   * Loads topology payload and renders map.
   * @returns {Promise<void>}
   */
  async function loadMapTopology() {
    var data = await authGet('/api/v2/map/topology');
    mapState.topology = data;
    renderTopology(data);
  }

  /**
   * Loads recent flows and animates unseen events.
   * @returns {Promise<void>}
   */
  async function loadMapFlows() {
    var svg = document.getElementById('network-svg');
    if (!svg) return;
    var data = await authGet('/api/v2/map/flows?minutes=30');
    var flows = (data.flows || []).slice(0, 24);
    flows.forEach(function (flow) {
      var key = [
        flow.timestamp || '',
        flow.source_type || '',
        flow.ip || '',
        flow.user || '',
      ].join('|');
      if (mapState.recentFlowKeys[key]) return;
      mapState.recentFlowKeys[key] = true;
      var pathId = mapState.pathBySubnet[flow.subnet_name];
      if (pathId) animateFlow(svg, pathId);
    });
  }

  /**
   * Loads Network Map tab data (topology + flows).
   * @returns {Promise<void>}
   */
  async function loadMapTab() {
    try {
      await loadMapTopology();
      await loadMapFlows();
    } catch (e) {
      showFlash('Map load failed: ' + e.message, false);
    }
  }

  window.loadMapTab = loadMapTab;
})();
