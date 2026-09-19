'use strict';
'require view';
'require fs';
'require ui';

function exec(command, args) {
	return fs.exec(command, args || []).then(function(res) {
		if (res.code !== 0)
			throw new Error((res.stderr || command + ' failed').trim());
		return res.stdout || '';
	});
}

function parseJSON(text, fallback) {
	try { return JSON.parse(text); } catch (e) { return fallback; }
}

function esc(v) {
	return String(v == null ? '' : v);
}

function table(title, headers, rows) {
	var body = rows.length ? rows.map(function(row) {
		return E('tr', {}, row.map(function(cell) { return E('td', {}, esc(cell)); }));
	}) : [ E('tr', {}, [ E('td', { 'colspan': headers.length }, _('No data')) ]) ];

	return E('div', { 'class': 'cbi-section' }, [
		E('h3', {}, title),
		E('div', { 'style': 'overflow-x:auto' }, [
			E('table', { 'class': 'table' }, [
				E('tr', { 'class': 'tr table-titles' }, headers.map(function(h) { return E('th', { 'class': 'th' }, h); }))
			].concat(body))
		])
	]);
}

function hookRows(ruleset) {
	var out = [];
	(ruleset.nftables || []).forEach(function(item) {
		var c = item.chain;
		if (c && c.hook)
			out.push([c.family || '', c.table || '', c.name || '', c.hook || '', c.prio != null ? c.prio : '', c.policy || '']);
	});
	return out.sort(function(a,b) { return Number(a[4] || 0) - Number(b[4] || 0); });
}

function ruleRows(rules) {
	return (rules || []).map(function(r) {
		return [r.priority != null ? r.priority : '', r.fwmark || '', r.fwmask || '', r.from || 'all', r.to || 'all', r.table || r.lookup || '', r.iif || r.iifname || '', r.oif || r.oifname || ''];
	});
}

function routeRows(routes) {
	return (routes || []).map(function(r) {
		return [r.table || 'main', r.dst || 'default', r.gateway || '', r.dev || '', r.protocol || '', r.metric != null ? r.metric : '', r.type || 'unicast'];
	});
}

return view.extend({
	load: function() {
		return Promise.all([
			exec('/usr/sbin/nft', ['-j', 'list', 'ruleset']),
			exec('/sbin/ip', ['-j', '-4', 'rule', 'show']),
			exec('/sbin/ip', ['-j', '-6', 'rule', 'show']),
			exec('/sbin/ip', ['-j', '-4', 'route', 'show', 'table', 'all']),
			exec('/sbin/ip', ['-j', '-6', 'route', 'show', 'table', 'all']),
			exec('/sbin/ip', ['-j', 'link', 'show'])
		]);
	},

	render: function(data) {
		var nft = parseJSON(data[0], {nftables: []});
		var rules4 = parseJSON(data[1], []);
		var rules6 = parseJSON(data[2], []);
		var routes4 = parseJSON(data[3], []);
		var routes6 = parseJSON(data[4], []);
		var links = parseJSON(data[5], []);

		var flow = E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, _('Packet Flow Map')),
			E('div', { 'style': 'display:flex;align-items:center;gap:.55em;flex-wrap:wrap;font-size:1.05em' }, [
				E('span', { 'class': 'label' }, _('Ingress')),
				E('span', {}, '→'),
				E('span', { 'class': 'label' }, _('Netfilter hooks / nftables')),
				E('span', {}, '→'),
				E('span', { 'class': 'label' }, _('RPDB / ip rule')),
				E('span', {}, '→'),
				E('span', { 'class': 'label' }, _('Routing table')),
				E('span', {}, '→'),
				E('span', { 'class': 'label' }, _('Egress interface'))
			]),
			E('p', { 'class': 'description' }, _('This first version is intentionally read-only. It visualizes the live kernel state instead of inferring it from UCI configuration.'))
		]);

		var linkRows = links.map(function(l) {
			return [l.ifindex || '', l.ifname || '', l.operstate || '', l.mtu || '', l.link_type || l.linkinfo && l.linkinfo.info_kind || '', (l.flags || []).join(', ')];
		});

		return E([], [
			E('h2', {}, _('Packet Flow Inspector')),
			E('p', {}, _('Read-only view of the live OpenWrt/Linux packet-routing pipeline.')),
			flow,
			table(_('Netfilter base chains'), [_('Family'), _('Table'), _('Chain'), _('Hook'), _('Priority'), _('Policy')], hookRows(nft)),
			table(_('IPv4 policy rules'), [_('Priority'), _('Mark'), _('Mask'), _('From'), _('To'), _('Table'), _('IIF'), _('OIF')], ruleRows(rules4)),
			table(_('IPv6 policy rules'), [_('Priority'), _('Mark'), _('Mask'), _('From'), _('To'), _('Table'), _('IIF'), _('OIF')], ruleRows(rules6)),
			table(_('IPv4 routes'), [_('Table'), _('Destination'), _('Gateway'), _('Device'), _('Protocol'), _('Metric'), _('Type')], routeRows(routes4)),
			table(_('IPv6 routes'), [_('Table'), _('Destination'), _('Gateway'), _('Device'), _('Protocol'), _('Metric'), _('Type')], routeRows(routes6)),
			table(_('Interfaces'), [_('Index'), _('Interface'), _('State'), _('MTU'), _('Kind'), _('Flags')], linkRows)
		]);
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
