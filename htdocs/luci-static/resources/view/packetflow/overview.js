'use strict';
'require view';
'require fs';
'require ui';

function safeExec(command, args) {
	return fs.exec(command, args || []).then(function(res) {
		return { ok: res.code === 0, stdout: res.stdout || '', stderr: res.stderr || '', code: res.code };
	}).catch(function(err) {
		return { ok: false, stdout: '', stderr: String(err), code: -1 };
	});
}

function parseJSON(text, fallback) {
	try { return JSON.parse(text); } catch (e) { return fallback; }
}

function esc(v) {
	if (Array.isArray(v)) return v.join(', ');
	if (v && typeof v === 'object') return JSON.stringify(v);
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

function markRows(ruleset) {
	var out = [];
	function walk(node, ctx) {
		if (!node || typeof node !== 'object') return;
		if (node.rule) {
			var r = node.rule;
			var next = { family:r.family || '', table:r.table || '', chain:r.chain || '', handle:r.handle || '' };
			(r.expr || []).forEach(function(e) { walk(e, next); });
			return;
		}
		if (node.mangle && node.mangle.key && (node.mangle.key.key === 'mark' || node.mangle.key.key === 'ct mark')) {
			out.push([ctx.family, ctx.table, ctx.chain, ctx.handle, esc(node.mangle.key), esc(node.mangle.value)]);
		}
		Object.keys(node).forEach(function(k) { if (k !== 'rule') walk(node[k], ctx); });
	}
	(ruleset.nftables || []).forEach(function(n) { walk(n, {}); });
	return out;
}

function diagnostics(rules4, rules6, routes4, routes6, links, hooks) {
	var warnings = [];
	var allRules = (rules4 || []).concat(rules6 || []);
	var allRoutes = (routes4 || []).concat(routes6 || []);
	var routeTables = {};
	var ifState = {};
	allRoutes.forEach(function(r) { routeTables[String(r.table || 'main')] = true; });
	links.forEach(function(l) { ifState[l.ifname] = l.operstate || 'UNKNOWN'; });

	allRules.forEach(function(r) {
		var t = String(r.table || r.lookup || '');
		if (t && t !== 'local' && t !== 'main' && t !== 'default' && !routeTables[t])
			warnings.push(['warning', _('Missing routing table'), _('Rule priority %s refers to table %s, but no route from that table is visible.').format(r.priority, t)]);
	});

	allRoutes.forEach(function(r) {
		if (r.dev && ifState[r.dev] && ifState[r.dev] === 'DOWN')
			warnings.push(['warning', _('Route uses DOWN interface'), _('%s route %s uses %s, which is DOWN.').format(r.table || 'main', r.dst || 'default', r.dev)]);
	});

	var hp = {};
	hooks.forEach(function(h) {
		var key = [h[0], h[3], h[4]].join('|');
		(hp[key] = hp[key] || []).push(h[1] + '/' + h[2]);
	});
	Object.keys(hp).forEach(function(k) {
		if (hp[k].length > 1)
			warnings.push(['info', _('Shared hook priority'), _('%s chains share %s. Ordering can depend on registration/order semantics: %s').format(hp[k].length, k, hp[k].join(', '))]);
	});

	return warnings;
}

function diagnosticBox(items) {
	return E('div', { 'class': 'cbi-section' }, [
		E('h3', {}, _('Diagnostics')),
		items.length ? E('div', {}, items.map(function(w) {
			return E('div', { 'class': 'alert-message ' + (w[0] === 'warning' ? 'warning' : 'notice'), 'style':'margin:.5em 0' }, [
				E('strong', {}, w[1] + ': '), w[2]
			]);
		})) : E('div', { 'class':'alert-message success' }, _('No obvious structural conflicts were detected by the current checks.'))
	]);
}

function flowGraph(rules, routes, links) {
	var tables = {};
	routes.forEach(function(r) {
		var t = String(r.table || 'main');
		(tables[t] = tables[t] || []).push(r);
	});
	var nodes = [];
	rules.forEach(function(r) {
		var t = String(r.table || r.lookup || '');
		if (!t) return;
		var defaults = (tables[t] || []).filter(function(x) { return !x.dst || x.dst === 'default'; });
		var outs = defaults.map(function(x) { return x.dev || x.gateway || '?'; });
		nodes.push(E('div', { 'style':'display:flex;align-items:center;gap:.45em;flex-wrap:wrap;margin:.35em 0' }, [
			E('span', { 'class':'label' }, 'prio ' + esc(r.priority)),
			E('span', {}, r.fwmark ? 'mark ' + esc(r.fwmark) : esc(r.from || 'all')),
			E('span', {}, '→'),
			E('span', { 'class':'label' }, 'table ' + t),
			E('span', {}, '→'),
			E('span', { 'class':'label' }, outs.length ? outs.join(', ') : _('no default route'))
		]));
	});
	return E('div', { 'class':'cbi-section' }, [
		E('h3', {}, _('Policy → Table → Egress relationships')),
		nodes.length ? E('div', {}, nodes) : E('p', {}, _('No policy-routing relationships found.'))
	]);
}

return view.extend({
	load: function() {
		return Promise.all([
			safeExec('/usr/sbin/nft', ['-j', 'list', 'ruleset']),
			safeExec('/sbin/ip', ['-j', '-4', 'rule', 'show']),
			safeExec('/sbin/ip', ['-j', '-6', 'rule', 'show']),
			safeExec('/sbin/ip', ['-j', '-4', 'route', 'show', 'table', 'all']),
			safeExec('/sbin/ip', ['-j', '-6', 'route', 'show', 'table', 'all']),
			safeExec('/sbin/ip', ['-j', 'link', 'show']),
			safeExec('/sbin/ip', ['-V']),
			safeExec('/usr/sbin/nft', ['--version'])
		]);
	},

	render: function(data) {
		var nft = parseJSON(data[0].stdout, {nftables: []});
		var rules4 = parseJSON(data[1].stdout, []);
		var rules6 = parseJSON(data[2].stdout, []);
		var routes4 = parseJSON(data[3].stdout, []);
		var routes6 = parseJSON(data[4].stdout, []);
		var links = parseJSON(data[5].stdout, []);
		var hooks = hookRows(nft);
		var errors = data.slice(0, 6).filter(function(x) { return !x.ok; });

		var traceResult = E('pre', { 'id':'packetflow-trace-result', 'style':'white-space:pre-wrap;min-height:3em' }, _('No trace query has been run.'));
		var dst = E('input', { 'class':'cbi-input-text', 'placeholder':'8.8.8.8', 'style':'max-width:16em' });
		var src = E('input', { 'class':'cbi-input-text', 'placeholder':'192.168.1.100', 'style':'max-width:16em' });
		var mark = E('input', { 'class':'cbi-input-text', 'placeholder':'0x100', 'style':'max-width:10em' });
		var iif = E('input', { 'class':'cbi-input-text', 'placeholder':'br-lan', 'style':'max-width:10em' });

		var trace = E('div', { 'class':'cbi-section' }, [
			E('h3', {}, _('Route Trace')),
			E('p', { 'class':'description' }, _('Performs a read-only kernel route lookup (ip route get). This is a routing decision probe, not a full nftables packet replay.')),
			E('div', { 'style':'display:flex;gap:.6em;flex-wrap:wrap;align-items:center' }, [
				E('label', {}, [_('Destination'), ' ', dst]),
				E('label', {}, [_('Source (optional)'), ' ', src]),
				E('label', {}, [_('Mark (optional)'), ' ', mark]),
				E('label', {}, [_('IIF (optional)'), ' ', iif]),
				E('button', { 'class':'btn cbi-button cbi-button-action', 'click': function() {
					var d = dst.value.trim(), s = src.value.trim(), m = mark.value.trim(), inf = iif.value.trim();
					if (!d || !/^[0-9A-Fa-f:.]+$/.test(d)) {
						ui.addNotification(null, E('p', {}, _('Destination must be an IPv4 or IPv6 address.')), 'warning');
						return;
					}
					if (s && !/^[0-9A-Fa-f:.]+$/.test(s)) {
						ui.addNotification(null, E('p', {}, _('Source must be an IPv4 or IPv6 address.')), 'warning');
						return;
					}
					if (m && !/^(0x[0-9A-Fa-f]+|[0-9]+)$/.test(m)) {
						ui.addNotification(null, E('p', {}, _('Mark must be decimal or hexadecimal.')), 'warning');
						return;
					}
					if (inf && !/^[A-Za-z0-9_.:@-]+$/.test(inf)) {
						ui.addNotification(null, E('p', {}, _('Invalid interface name.')), 'warning');
						return;
					}
					var family = d.indexOf(':') >= 0 ? '-6' : '-4';
					var args = ['-j', family, 'route', 'get', d];
					if (s) args.push('from', s);
					if (m) args.push('mark', m);
					if (inf) args.push('iif', inf);
					traceResult.textContent = _('Running…');
					safeExec('/sbin/ip', args).then(function(res) {
						if (!res.ok) traceResult.textContent = _('Lookup failed: ') + res.stderr;
						else {
							var obj = parseJSON(res.stdout, []);
							traceResult.textContent = JSON.stringify(obj, null, 2);
						}
					});
				}}, _('Trace'))
			]),
			traceResult
		]);

		var flow = E('div', { 'class':'cbi-section' }, [
			E('h3', {}, _('Packet Flow Map')),
			E('div', { 'style':'display:flex;align-items:center;gap:.55em;flex-wrap:wrap;font-size:1.05em' }, [
				E('span', { 'class':'label' }, _('Ingress')), E('span', {}, '→'),
				E('span', { 'class':'label' }, _('Netfilter hooks / nftables')), E('span', {}, '→'),
				E('span', { 'class':'label' }, _('RPDB / ip rule')), E('span', {}, '→'),
				E('span', { 'class':'label' }, _('Routing table')), E('span', {}, '→'),
				E('span', { 'class':'label' }, _('Egress interface'))
			])
		]);

		var linkRows = links.map(function(l) {
			return [l.ifindex || '', l.ifname || '', l.operstate || '', l.mtu || '', l.link_type || (l.linkinfo && l.linkinfo.info_kind) || '', (l.flags || []).join(', ')];
		});

		var errBox = errors.length ? E('div', { 'class':'alert-message warning' },
			_('Some live-state collectors failed; available sections are still shown. Check that nftables and ip-full are installed.')) : null;

		return E([], [
			E('h2', {}, _('Packet Flow Inspector')),
			E('p', {}, _('Read-only view of the effective OpenWrt/Linux networking state.')),
			errBox,
			E('p', { 'class':'description' }, esc(data[6].stdout.trim()) + ' · ' + esc(data[7].stdout.trim())),
			flow,
			flowGraph(rules4.concat(rules6), routes4.concat(routes6), links),
			diagnosticBox(diagnostics(rules4, rules6, routes4, routes6, links, hooks)),
			trace,
			table(_('Netfilter base chains'), [_('Family'), _('Table'), _('Chain'), _('Hook'), _('Priority'), _('Policy')], hooks),
			table(_('Packet/connection mark setters'), [_('Family'), _('Table'), _('Chain'), _('Handle'), _('Key'), _('Value')], markRows(nft)),
			table(_('IPv4 policy rules'), [_('Priority'), _('Mark'), _('Mask'), _('From'), _('To'), _('Table'), _('IIF'), _('OIF')], ruleRows(rules4)),
			table(_('IPv6 policy rules'), [_('Priority'), _('Mark'), _('Mask'), _('From'), _('To'), _('Table'), _('IIF'), _('OIF')], ruleRows(rules6)),
			table(_('IPv4 routes'), [_('Table'), _('Destination'), _('Gateway'), _('Device'), _('Protocol'), _('Metric'), _('Type')], routeRows(routes4)),
			table(_('IPv6 routes'), [_('Table'), _('Destination'), _('Gateway'), _('Device'), _('Protocol'), _('Metric'), _('Type')], routeRows(routes6)),
			table(_('Interfaces'), [_('Index'), _('Interface'), _('State'), _('MTU'), _('Kind'), _('Flags')], linkRows)
		].filter(Boolean));
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
