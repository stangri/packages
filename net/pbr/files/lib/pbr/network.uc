'use strict';
// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright 2020-2026 MOSSDeF, Stan Grishin (stangri@melmac.ca).
//
// Network state, interface queries, protocol detection, gateway discovery.

function create_network(fs_mod, config, sh, pkg, platform, V) {
	let readfile = fs_mod.readfile;
	let stat = fs_mod.stat;
	let lsdir = fs_mod.lsdir;

	let cfg = config.cfg;
	let env = platform.env;

	function network_get_device(iface) {
		let iface_status = config.ubus_call('network.interface.' + iface, 'status');
		return iface_status?.l3_device || iface_status?.device || null;
	}

	function network_get_physdev(iface) {
		let iface_status = config.ubus_call('network.interface.' + iface, 'status');
		return iface_status?.device || null;
	}

	function network_get_gateway(iface) {
		let iface_status = config.ubus_call('network.interface.' + iface, 'status');
		if (!iface_status) return null;
		let routes = iface_status?.route;
		if (type(routes) == 'array') {
			for (let r in routes) {
				if (r?.target == '0.0.0.0' && r?.mask == 0)
					return r?.nexthop;
			}
		}
		return null;
	}

	function network_get_gateway6(iface) {
		let iface_status = config.ubus_call('network.interface.' + iface, 'status');
		if (!iface_status) return null;
		let routes = iface_status?.route;
		if (type(routes) == 'array') {
			for (let r in routes) {
				if (r?.target == '::' && r?.mask == 0)
					return r?.nexthop;
			}
		}
		return null;
	}

	function network_get_protocol(iface) {
		let ctx = config.uci_ctx('network');
		return ctx.get('network', iface, 'proto') || null;
	}

	function uci_get_device(iface) {
		let ctx = config.uci_ctx('network');
		return ctx.get('network', iface, 'device') || ctx.get('network', iface, 'dev') || null;
	}

	// ── Protocol Detectors ──────────────────────────────────────────

	function is_dslite(iface) { let _p = network_get_protocol(iface); return _p != null && substr(_p, 0, 6) == 'dslite'; }
	function is_l2tp(iface) { let _p = network_get_protocol(iface); return _p != null && substr(_p, 0, 4) == 'l2tp'; }
	function is_oc(iface) { let _p = network_get_protocol(iface); return _p != null && substr(_p, 0, 11) == 'openconnect'; }
	function is_ovpn(iface) {
		let ctx = config.uci_ctx('network');
		let d = ctx.get('network', iface, 'device') || ctx.get('network', iface, 'dev');
		let p = network_get_protocol(iface);
		if (d && (substr(d, 0, 3) == 'tun' || substr(d, 0, 3) == 'tap')) return true;
		if (p && substr(p, 0, 7) == 'openvpn') return true;
		if (d && stat('/sys/devices/virtual/net/' + d + '/tun_flags')?.type != null) return true;
		return false;
	}
	function is_pptp(iface) { let _p = network_get_protocol(iface); return _p != null && substr(_p, 0, 4) == 'pptp'; }
	function is_softether(iface) { let d = network_get_device(iface); return d != null && substr(d, 0, 4) == 'vpn_'; }
	function is_netbird(iface) { let d = network_get_device(iface); return d != null && substr(d, 0, 2) == 'wt'; }
	function is_tailscale(iface) { let d = network_get_device(iface); return d != null && substr(d, 0, 9) == 'tailscale'; }
	function is_wg(iface) { let _p = network_get_protocol(iface); return !config.uci_ctx('network').get('network', iface, 'listen_port') && _p != null && substr(_p, 0, 9) == 'wireguard'; }
	function is_wg_server(iface) { let _p = network_get_protocol(iface); return !!config.uci_ctx('network').get('network', iface, 'listen_port') && _p != null && substr(_p, 0, 9) == 'wireguard'; }
	function is_tor(iface) { return lc(iface) == 'tor'; }
	function get_xray_traffic_port(iface) {
		if (!iface) return null;
		let i = replace('' + iface, pkg.xray_iface_prefix, '');
		if (i == '' + iface) return null;
		return i;
	}
	function is_xray(iface) { return get_xray_traffic_port(iface) != null; }
	function is_tunnel(iface) {
		return is_dslite(iface) || is_l2tp(iface) || is_oc(iface) || is_ovpn(iface) ||
			is_pptp(iface) || is_softether(iface) || is_netbird(iface) ||
			is_tailscale(iface) || is_tor(iface) || is_wg(iface);
	}

	// ── Interface Classification ────────────────────────────────────

	function is_wan(iface) {
		if (!iface) return false;
		iface = '' + iface;
		let is6 = !!match(iface, /wan.*6$/) || !!match(iface, /.*wan6$/);
		if (is6) return !!cfg.ipv6_enabled;
		return !!match(iface, /wan/) || !!match(iface, /.*wan$/);
	}
	function is_uplink4(iface) { return iface == cfg.uplink_interface4; }
	function is_uplink6(iface) { return !!cfg.ipv6_enabled && iface == cfg.uplink_interface6; }
	function is_uplink(iface) { return is_uplink4(iface) || is_uplink6(iface); }
	function is_split_uplink() { return !!cfg.ipv6_enabled && cfg.uplink_interface4 != cfg.uplink_interface6; }
	function is_default_dev(dev) {
		let out = sh.exec(pkg.ip_full + ' -4 route show default 2>/dev/null');
		let m = match(out, /dev\s+(\S+)/);
		return m ? dev == m[1] : false;
	}
	function is_disabled_interface(iface) { return config.uci_ctx('network').get('network', iface, 'disabled') == '1'; }
	function is_lan(iface) {
		let d = network_get_device(iface);
		if (!d) return false;
		return V.str_contains(cfg.lan_device, d);
	}
	function is_ignored_interface(iface) { return V.str_contains_word(cfg.ignored_interface, iface); }
	function is_tor_running() {
		if (is_ignored_interface('tor')) return false;
		let content = readfile(pkg.tor_config_file);
		if (!content || content == '') return false;
		let svc = config.ubus_call('service', 'list', { name: 'tor' });
		if (!svc?.tor?.instances) return false;
		for (let k in keys(svc.tor.instances)) {
			if (svc.tor.instances[k]?.running == true)
				return true;
		}
		return false;
	}
	function is_ignore_target(iface) { return lc(iface) == 'ignore'; }
	function is_netifd_table(name) { let c = readfile('/etc/config/network') || ''; return index(c, name) >= 0 && !!match(c, regexp('ip.table.*' + name)); }
	function is_netifd_interface(iface) {
		let ctx = config.uci_ctx('network');
		let ip4t = ctx.get('network', iface, 'ip4table');
		let ip6t = ctx.get('network', iface, 'ip6table');
		return !!(ip4t || ip6t);
	}
	function is_mwan4_interface(iface) {
		return !!(iface && env.mwan4_mark[iface]);
	}
	function is_netifd_interface_default(iface) {
		if (!is_netifd_interface(iface)) return false;
		if (cfg.netifd_interface_default == iface) return true;
		if (cfg.netifd_interface_default6 == iface) return true;
		return false;
	}
	function is_supported_protocol(proto) {
		if (!proto) return false;
		return !!env.protocols[lc(proto)];
	}
	function is_mwan4_strategy(iface) { return iface && index(iface, 'mwan4_strategy_') == 0; }
	function is_supported_interface(iface) {
		if (!iface) return false;
		if (is_lan(iface) || is_disabled_interface(iface)) return false;
		if (V.str_contains_word(cfg.supported_interface, iface)) return true;
		if (!is_ignored_interface(iface) && (is_uplink(iface) || is_wan(iface) || is_tunnel(iface))) return true;
		if (is_ignore_target(iface)) return true;
		if (is_xray(iface)) return true;
		return false;
	}
	function is_config_enabled(section_type) {
		let result = false;
		let ctx = config.uci_ctx(pkg.name);
		ctx.foreach(pkg.name, section_type, function(s) {
			if ((s.enabled || '1') == '1') result = true;
		});
		return result;
	}

	// ── Gateway Helpers ─────────────────────────────────────────────

	function get_gateway4(iface, dev) {
		let gw = network_get_gateway(iface);
		if (!gw || gw == '0.0.0.0') {
			let out = sh.exec(pkg.ip_full + ' -4 a list dev ' + sh.quote(dev) + ' 2>/dev/null');
			let m = match(out, /inet\s+([0-9.]+)/);
			gw = m ? m[1] : '';
		}
		return gw;
	}

	function get_gateway6(iface, dev) {
		if (is_uplink4(iface)) iface = cfg.uplink_interface6;
		let gw = network_get_gateway6(iface);
		if (!gw || gw == '::/0' || gw == '::0/0' || gw == '::') {
			let out = sh.exec(pkg.ip_full + ' -6 a list dev ' + sh.quote(dev) + ' 2>/dev/null');
			let m = match(out, /inet6\s+(\S+)\s+scope global/);
			gw = m ? m[1] : '';
		}
		return gw;
	}

	// ── load() ──────────────────────────────────────────────

	function load(param) {
		if (!env.ifaces_supported || env.ifaces_supported == '') {
			let ctx_fw = config.uci_ctx('firewall', true);
			ctx_fw.foreach('firewall', 'zone', function(s) {
				if (s.name == 'wan') env.firewall_wan_zone = s['.name'];
			});

			let parts = [];
			let webui_parts = [];
			config.uci_ctx('network', true).foreach('network', 'interface', function(s) {
				let iface = s['.name'];
				if (is_supported_interface(iface)) {
					push(parts, iface);
					push(webui_parts, iface);
				}
			});
			// Add mwan4 strategies
			for (let strategy in keys(env.mwan4_strategy_chain)) {
				push(webui_parts, 'mwan4_strategy_' + strategy);
			}
			push(webui_parts, 'ignore');
			env.ifaces_supported = join(' ', parts);
			env.webui_interfaces = webui_parts;
		}

		// Discover gateways
		if (!env.uplink_gw) {
			let dev4 = network_get_device(cfg.uplink_interface4) || network_get_physdev(cfg.uplink_interface4) || '';
			let gw4 = get_gateway4(cfg.uplink_interface4, dev4);
			env.uplink_gw4 = gw4 || '';
			if (cfg.ipv6_enabled && cfg.uplink_interface6) {
				let dev6 = network_get_device(cfg.uplink_interface6) || network_get_physdev(cfg.uplink_interface6) || dev4;
				let gw6 = get_gateway6(cfg.uplink_interface6, dev6);
				env.uplink_gw6 = gw6 || '';
			}
			env.uplink_gw = env.uplink_gw4 || env.uplink_gw6 || '';
		}
	}

	function is_wan_up(param, errors) {
		let ctx = config.uci_ctx('network');
		if (!ctx.get('network', cfg.uplink_interface4)) {
			push(errors, { code: 'errorNoUplinkInterface', info: cfg.uplink_interface4 });
			push(errors, { code: 'errorNoUplinkInterfaceHint', info: pkg.url('#uplink_interface') });
			return false;
		}
		config.network_flush_cache();
		load(param);
		if (env.uplink_gw) {
			return true;
		} else {
			push(errors, { code: 'errorNoUplinkGateway' });
			return false;
		}
	}

	return {
		network_get_device,
		network_get_physdev,
		network_get_gateway,
		network_get_gateway6,
		network_get_protocol,
		uci_get_device,
		is_dslite, is_l2tp, is_oc, is_ovpn, is_pptp,
		is_softether, is_netbird, is_tailscale,
		is_wg, is_wg_server, is_tor, is_xray, is_tunnel,
		get_xray_traffic_port,
		is_wan, is_uplink, is_uplink4, is_uplink6, is_split_uplink,
		is_default_dev, is_disabled_interface, is_lan,
		is_ignored_interface, is_tor_running,
		is_ignore_target, is_netifd_table, is_netifd_interface,
		is_mwan4_interface, is_netifd_interface_default,
		is_supported_protocol, is_mwan4_strategy,
		is_supported_interface, is_config_enabled,
		get_gateway4, get_gateway6,
		load, is_wan_up,
	};
}

export default create_network;
