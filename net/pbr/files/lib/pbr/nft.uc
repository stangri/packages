'use strict';
// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright 2020-2026 MOSSDeF, Stan Grishin (stangri@melmac.ca).
//
// NFT rule building, nftset management, cleanup, resolver, address classification.

function create_nft(fs_mod, config, sh, output, pkg, platform, network, V, state) {
	let readfile = fs_mod.readfile;
	let writefile = fs_mod.writefile;
	let stat = fs_mod.stat;
	let unlink = fs_mod.unlink;
	let _open = fs_mod.open;
	let _dirname = fs_mod.dirname;

	let cfg = config.cfg;
	let env = platform.env;

	// ── Internal State ────────────────────────────────────────────────
	let nft_lines = [];
	let _mark_chains_created = {};
	let nft_fw4_dump = '';
	let resolver_working_flag = false;
	let resolver_stored_hash = '';
	let dnsmasq_ubus = null;

	// Forward declaration (circular: resolveip_to_nftset → resolver → nftset → resolveip_to_nftset)
	let resolver = {};

	// ── NFT Query Helpers ─────────────────────────────────────────────

	function get_rt_tables_id(iface) {
		let content = readfile(pkg.rt_tables_file) || '';
		let esc_iface = replace(iface, /([.+*?^${}()|[\]\\])/g, '\\$1');
		let pattern = regexp('(^|\\n)(\\d+)\\s+' + pkg.ip_table_prefix + '_' + esc_iface + '(\\n|$)');
		let m = match(content, pattern);
		return m ? m[2] : '';
	}

	function get_rt_tables_next_id() {
		let out = sh.exec("sort -r -n " + sh.quote(pkg.rt_tables_file) + " | grep -o -E -m 1 '^[0-9]+'");
		return '' + ((int(out) || 0) + 1);
	}

	function get_rt_tables_non_pbr_next_id() {
		let out = sh.exec("grep -v " + sh.quote(pkg.ip_table_prefix + '_') + " " + sh.quote(pkg.rt_tables_file) + " | sort -r -n | grep -o -E -m 1 '^[0-9]+'");
		return '' + ((int(out) || 0) + 1);
	}

	function get_mark_nft_chains() {
		let out = sh.exec('nft list table inet ' + pkg.nft_table + ' 2>/dev/null');
		let prefix = pkg.nft_prefix + '_mark_';
		let results = [];
		for (let line in split(out, '\n')) {
			let m = match(line, /chain\s+(\S+)/);
			if (m && index(m[1], prefix) == 0) push(results, m[1]);
		}
		return join(' ', results);
	}

	function get_external_mark_chains() {
		let external = {};
		let chain_re = regexp('chain\\s+(' + pkg.nft_prefix + '_mark_\\S+)');
		let netifd_nft = readfile(pkg.nft_netifd_file) || '';
		for (let line in split(netifd_nft, '\n')) {
			let m = match(line, chain_re);
			if (m) external[m[1]] = true;
		}
		let mwan4_nft = readfile(pkg.mwan4_nft_iface_file) || '';
		for (let line in split(mwan4_nft, '\n')) {
			let m = match(line, chain_re);
			if (m) external[m[1]] = true;
		}
		return external;
	}

	function is_service_running_nft() {
		if (!env.nft_installed) return false;
		let chains = get_mark_nft_chains();
		return chains != null && chains != '';
	}

	function get_nft_sets() {
		let out = sh.exec('nft list table inet ' + pkg.nft_table + ' 2>/dev/null');
		let prefix = pkg.nft_prefix + '_';
		let results = [];
		for (let line in split(out, '\n')) {
			let m = match(line, /set\s+(\S+)/);
			if (m && index(m[1], prefix) == 0) push(results, m[1]);
		}
		return join(' ', results);
	}

	// ── Resolve Helpers ───────────────────────────────────────────────

	function resolveip_to_nftset(...args) {
		resolver.wait();
		let out = sh.exec('resolveip ' + join(' ', map(args, (a) => sh.quote(a))));
		let ips = filter(split(trim(out), '\n'), (l) => length(l) > 0);
		return join(',', ips);
	}

	function resolveip_to_nftset4(host) {
		return resolveip_to_nftset('-4', host);
	}

	function resolveip_to_nftset6(host) {
		if (!cfg.ipv6_enabled) return '';
		return resolveip_to_nftset('-6', host);
	}

	function ipv4_leases_to_nftset(arg) {
		let content = readfile('/tmp/dhcp.leases') || '';
		if (!content) return '';
		let results = [];
		for (let line in split(content, '\n')) {
			if (index(line, arg) >= 0) {
				let parts = split(trim(line), /\s+/);
				if (length(parts) >= 3 && parts[2]) push(results, parts[2]);
			}
		}
		return join(',', results);
	}

	function ipv6_leases_to_nftset(arg) {
		let content = readfile('/tmp/hosts/odhcpd') || '';
		if (!content) return '';
		let results = [];
		for (let line in split(content, '\n')) {
			if (index(line, arg) >= 0) {
				let parts = split(trim(line), /\s+/);
				if (length(parts) >= 1 && parts[0]) push(results, parts[0]);
			}
		}
		return join(',', results);
	}

	// ── NFT Operations ────────────────────────────────────────────────

	function nft_add(line) {
		if (line) push(nft_lines, line);
	}

	function nft4(line) {
		nft_add(line);
		return true;
	}

	function nft6(line) {
		if (!cfg.ipv6_enabled) return true;
		nft_add(line);
	}

	function nft_call(...args) {
		return sh.run('nft ' + join(' ', args)) == 0;
	}

	function nft_check_element(element_type, name) {
		if (!nft_fw4_dump)
			nft_fw4_dump = sh.exec('nft list table inet fw4 2>&1');
		if (element_type == 'table' && name == 'fw4')
			return !!(nft_fw4_dump && nft_fw4_dump != '');
		let lines = split(nft_fw4_dump, '\n');
		for (let line in lines) {
			if (index(line, element_type) >= 0 && index(line, name) >= 0)
				return true;
		}
		return false;
	}

	function ensure_mark_chain(mark, chain_name) {
		if (_mark_chains_created[mark]) return;
		_mark_chains_created[mark] = true;
		let rule_params = cfg._nft_rule_params ? ' ' + cfg._nft_rule_params : '';
		nft_add('add chain inet ' + pkg.nft_table + ' ' + chain_name);
		nft_add('add rule inet ' + pkg.nft_table + ' ' + chain_name + rule_params +
			' meta mark set (meta mark & ' + cfg.fw_maskXor + ') | ' + mark);
		nft_add('add rule inet ' + pkg.nft_table + ' ' + chain_name + ' return');
	}

	// ── NFT File Operations ───────────────────────────────────────────

	let nft_file = {};

	nft_file.append = function(target, ...extra) {
		let line = join(' ', extra);
		if (line) push(nft_lines, line);
		return true;
	};

	nft_file.init = function(target, iface_registry) {
		let nft_prefix = pkg.nft_prefix;
		let nft_table = pkg.nft_table;
		let chains_list = pkg.chains_list;

		switch (target) {
		case 'main': {
			unlink(pkg.nft_temp_file);
			unlink(pkg.nft_main_file);
			sh.mkdir_p(_dirname(pkg.nft_temp_file));
			sh.mkdir_p(_dirname(pkg.nft_main_file));
			nft_lines = [];
			_mark_chains_created = {};
			push(nft_lines, 'define ' + nft_prefix + '_fw_mark = ' + cfg.fw_mask);
			push(nft_lines, 'define ' + nft_prefix + '_fw_mask = ' + cfg.fw_maskXor);
			if (iface_registry) {
				for (let iname in keys(iface_registry)) {
					let idata = iface_registry[iname];
					if (type(idata) == 'function') continue;
					if (idata?.chain_name) {
						push(nft_lines, 'define ' + nft_prefix + '_' + iname + '_chain = ' + idata.chain_name);
					}
				}
			}
			push(nft_lines, '');
			let chains = split(chains_list, ' ');
			for (let ch in ['dstnat', ...chains])
				push(nft_lines, 'add chain inet ' + nft_table + ' ' + nft_prefix + '_' + ch + ' {}');
			push(nft_lines, '');
			push(nft_lines, 'insert rule inet ' + nft_table + ' dstnat jump ' + nft_prefix + '_dstnat');
			push(nft_lines, 'add rule inet ' + nft_table + ' mangle_prerouting jump ' + nft_prefix + '_prerouting');
			push(nft_lines, 'add rule inet ' + nft_table + ' mangle_output jump ' + nft_prefix + '_output');
			push(nft_lines, 'add rule inet ' + nft_table + ' mangle_forward jump ' + nft_prefix + '_forward');
			push(nft_lines, '');
			let rule_params = cfg._nft_rule_params ? ' ' + cfg._nft_rule_params : '';
			for (let ch in chains)
				push(nft_lines, 'add rule inet ' + nft_table + ' ' + nft_prefix + '_' + ch +
					rule_params + ' meta mark & ' + cfg.fw_mask + ' != 0 return');
			break;
		}
		case 'netifd':
			unlink(pkg.nft_temp_file);
			unlink(pkg.nft_netifd_file);
			sh.mkdir_p(_dirname(pkg.nft_temp_file));
			sh.mkdir_p(_dirname(pkg.nft_netifd_file));
			nft_lines = [];
			break;
		}
		return true;
	};

	nft_file.remove = function(target) {
		switch (target) {
		case 'main':
			nft_lines = [];
			unlink(pkg.nft_temp_file);
			unlink(pkg.nft_main_file);
			break;
		case 'netifd':
			output.info.write('Removing fw4 netifd nft file ');
			output.verbose.write('Removing fw4 netifd nft file ');
			if (unlink(pkg.nft_netifd_file) != false) {
				output.okbn();
			} else {
				push(state.errors, { code: 'errorNftNetifdFileDelete', info: pkg.nft_netifd_file });
				output.failn();
			}
			break;
		}
		return true;
	};

	nft_file.exists = function(target) {
		switch (target) {
		case 'main': {
			let sm = stat(pkg.nft_main_file);
			return sm != null && sm.size > 0;
		}
		case 'netifd': {
			let sn = stat(pkg.nft_netifd_file);
			return sn != null && sn.size > 0;
		}
		}
		return false;
	};

	nft_file.get_content = function() {
		if (!length(nft_lines)) return null;
		return '#!/usr/sbin/nft -f\n\n' + join('\n', nft_lines) + '\n';
	};

	nft_file.apply = function(target) {
		switch (target) {
		case 'main': {
			if (!length(nft_lines)) return false;
			sh.mkdir_p(_dirname(pkg.nft_temp_file));
			sh.mkdir_p(_dirname(pkg.nft_main_file));
			writefile(pkg.nft_temp_file, '#!/usr/sbin/nft -f\n\n' + join('\n', nft_lines) + '\n');
			output.info.write('Installing fw4 nft file ');
			output.verbose.write('Installing fw4 nft file ');
			if (nft_call('-c', '-f', pkg.nft_temp_file) &&
				sh.run('cp -f ' + sh.quote(pkg.nft_temp_file) + ' ' + sh.quote(pkg.nft_main_file)) == 0) {
				output.okn();
				sh.run('fw4 -q reload');
				return true;
			} else {
				push(state.errors, { code: 'errorNftMainFileInstall', info: pkg.nft_temp_file });
				output.failn();
				return false;
			}
		}
		case 'netifd': {
			if (!length(nft_lines)) return false;
			sh.mkdir_p(_dirname(pkg.nft_temp_file));
			sh.mkdir_p(_dirname(pkg.nft_netifd_file));
			writefile(pkg.nft_temp_file, '#!/usr/sbin/nft -f\n\n' + join('\n', nft_lines) + '\n');
			output.info.write('Installing fw4 netifd nft file ');
			output.verbose.write('Installing fw4 netifd nft file ');
			if (nft_call('-c', '-f', pkg.nft_temp_file) &&
				sh.run('cp -f ' + sh.quote(pkg.nft_temp_file) + ' ' + sh.quote(pkg.nft_netifd_file)) == 0) {
				output.okbn();
				return true;
			} else {
				push(state.errors, { code: 'errorNftNetifdFileInstall', info: pkg.nft_temp_file });
				output.failn();
				return false;
			}
		}
		}
		return true;
	};

	nft_file.match = function(target, ...extra) {
		let pattern = length(extra) > 0 ? extra[0] : '';
		let content = join('\n', nft_lines);
		return index(content, pattern) >= 0;
	};

	nft_file.filter = function(target, ...extra) {
		let pattern = length(extra) > 0 ? extra[0] : '';
		if (pattern)
			nft_lines = filter(nft_lines, l => index(l, pattern) < 0);
		return true;
	};

	nft_file.sed = function(target, ...extra) {
		let sed_args2 = join(' ', extra);
		sh.run('sed -i ' + sed_args2 + ' ' + sh.quote(pkg.nft_netifd_file));
		return true;
	};

	nft_file.show = function(target) {
		switch (target) {
		case 'main': {
			let content_m = readfile(pkg.nft_main_file) || '';
			let lines_m = split(content_m, '\n');
			let result_m = pkg.name + ' fw4 nft file: ' + pkg.nft_main_file + '\n';
			for (let i = 2; i < length(lines_m); i++)
				result_m += lines_m[i] + '\n';
			return result_m;
		}
		case 'netifd': {
			let content_n = readfile(pkg.nft_netifd_file) || '';
			let lines_n = split(content_n, '\n');
			let result_n = pkg.name + ' fw4 netifd nft file: ' + pkg.nft_netifd_file + '\n';
			for (let i = 2; i < length(lines_n); i++)
				result_n += lines_n[i] + '\n';
			return result_n;
		}
		}
		return '';
	};

	// ── nftset operations ─────────────────────────────────────────────

	function get_set_name(iface, family, target, type_val, uid) {
		return pkg.nft_prefix + '_' + (iface ? iface + '_' : '') + (family || '4') +
			(target ? '_' + target : '') + (type_val ? '_' + type_val : '') + (uid ? '_' + uid : '');
	}

	let nftset = {};

	let _nftset_names = function(iface, target, type_val, uid) {
		target = target || 'dst';
		type_val = type_val || 'ip';
		let n4 = get_set_name(iface, '4', target, type_val, uid);
		let n6 = get_set_name(iface, '6', target, type_val, uid);
		if (length(n4) > 255) {
			push(state.errors, { code: 'errorNftsetNameTooLong', info: n4 });
			return null;
		}
		return { n4, n6, target, type_val };
	};

	let _nftset_result = function(v4_ok, v6_ok) {
		if (!cfg.ipv6_enabled) v6_ok = false;
		return v4_ok || v6_ok;
	};

	nftset.add = function(iface, target, type_val, uid, param) {
		let ns = _nftset_names(iface, target, type_val, uid);
		if (!ns) return false;
		let v4_ok = false, v6_ok = false;
		let nft_table = pkg.nft_table;
		if (V.is_mac_address(param) || index('' + param, ',') >= 0 || index('' + param, ' ') >= 0) {
			nft4('add element inet ' + nft_table + ' ' + ns.n4 + ' { ' + param + ' }');
			v4_ok = true;
			nft6('add element inet ' + nft_table + ' ' + ns.n6 + ' { ' + param + ' }');
			v6_ok = true;
		} else if (V.is_ipv4(param)) {
			nft4('add element inet ' + nft_table + ' ' + ns.n4 + ' { ' + param + ' }');
			v4_ok = true;
		} else if (V.is_ipv6(param)) {
			nft6('add element inet ' + nft_table + ' ' + ns.n6 + ' { ' + param + ' }');
			v6_ok = true;
		} else {
			let param4 = '', param6 = '';
			if (ns.target == 'src') {
				param4 = ipv4_leases_to_nftset(param);
				param6 = ipv6_leases_to_nftset(param);
			}
			if (!param4) param4 = resolveip_to_nftset4(param);
			if (!param6) param6 = resolveip_to_nftset6(param);
			if (!param4 && !param6) {
				push(state.errors, { code: 'errorFailedToResolve', info: param });
			} else {
				if (param4) { nft4('add element inet ' + nft_table + ' ' + ns.n4 + ' { ' + param4 + ' }'); v4_ok = true; }
				if (param6) { nft6('add element inet ' + nft_table + ' ' + ns.n6 + ' { ' + param6 + ' }'); v6_ok = true; }
			}
		}
		return _nftset_result(v4_ok, v6_ok);
	};

	nftset.add_dnsmasq_element = function(iface, target, type_val, uid, comment, param) {
		let ns = _nftset_names(iface, target, type_val, uid);
		if (!ns) return false;
		let nft_table = pkg.nft_table;
		let n6 = cfg.ipv6_enabled ? ns.n6 : '';
		let entry = 'nftset=/' + param + '/4#inet#' + nft_table + '#' + ns.n4 +
			(n6 ? ',6#inet#' + nft_table + '#' + n6 : '') +
			' # ' + comment;
		let existing = readfile(pkg.dnsmasq_file) || '';
		if (index(existing, entry) >= 0) return true;
		let fh = _open(pkg.dnsmasq_file, 'a');
		if (fh) {
			fh.write(entry + '\n');
			fh.close();
			return _nftset_result(true, false);
		}
		return false;
	};

	nftset.create = function(iface, target, type_val, uid, comment) {
		let ns = _nftset_names(iface, target, type_val, uid);
		if (!ns) return false;
		let nft_table = pkg.nft_table;
		let v4_ok = false, v6_ok = false;
		switch (ns.type_val) {
		case 'ip':
		case 'net':
			nft4('add set inet ' + nft_table + ' ' + ns.n4 + ' { type ipv4_addr;' + cfg._nft_set_params + ' comment "' + comment + '";}');
			v4_ok = true;
			nft6('add set inet ' + nft_table + ' ' + ns.n6 + ' { type ipv6_addr;' + cfg._nft_set_params + ' comment "' + comment + '";}');
			v6_ok = true;
			break;
		case 'mac':
			nft4('add set inet ' + nft_table + ' ' + ns.n4 + ' { type ether_addr;' + cfg._nft_set_params + ' comment "' + comment + '";}');
			v4_ok = true;
			nft6('add set inet ' + nft_table + ' ' + ns.n6 + ' { type ether_addr;' + cfg._nft_set_params + ' comment "' + comment + '";}');
			v6_ok = true;
			break;
		}
		return _nftset_result(v4_ok, v6_ok);
	};

	nftset.create_dnsmasq = function(iface, target, type_val, uid, comment) {
		let ns = _nftset_names(iface, target, type_val, uid);
		if (!ns) return false;
		let nft_table = pkg.nft_table;
		nft4('add set inet ' + nft_table + ' ' + ns.n4 + ' { type ipv4_addr;' + cfg._nft_set_params + ' comment "' + comment + '";}');
		nft6('add set inet ' + nft_table + ' ' + ns.n6 + ' { type ipv6_addr;' + cfg._nft_set_params + ' comment "' + comment + '";}');
		return _nftset_result(true, true);
	};

	nftset.create_user = function(iface, target, type_val, uid, comment, mark) {
		let ns = _nftset_names(iface, target, type_val, uid);
		if (!ns) return false;
		let nft_prefix = pkg.nft_prefix;
		let nft_table = pkg.nft_table;
		let v4_ok = false, v6_ok = false;
		switch (ns.type_val) {
		case 'ip':
		case 'net':
			nft4('add set inet ' + nft_table + ' ' + ns.n4 + ' { type ipv4_addr;' + cfg._nft_set_params + ' comment "' + comment + '";}');
			v4_ok = true;
			nft6('add set inet ' + nft_table + ' ' + ns.n6 + ' { type ipv6_addr;' + cfg._nft_set_params + ' comment "' + comment + '";}');
			v6_ok = true;
			if (ns.target == 'dst') {
				nft4('add rule inet ' + nft_table + ' ' + nft_prefix + '_prerouting ' + pkg.nft_ipv4_flag + ' daddr @' + ns.n4 + ' ' + cfg._nft_rule_params + ' goto ' + nft_prefix + '_mark_' + mark);
				nft6('add rule inet ' + nft_table + ' ' + nft_prefix + '_prerouting ' + pkg.nft_ipv6_flag + ' daddr @' + ns.n6 + ' ' + cfg._nft_rule_params + ' goto ' + nft_prefix + '_mark_' + mark);
			} else if (ns.target == 'src') {
				nft4('add rule inet ' + nft_table + ' ' + nft_prefix + '_prerouting ' + pkg.nft_ipv4_flag + ' saddr @' + ns.n4 + ' ' + cfg._nft_rule_params + ' goto ' + nft_prefix + '_mark_' + mark);
				nft6('add rule inet ' + nft_table + ' ' + nft_prefix + '_prerouting ' + pkg.nft_ipv6_flag + ' saddr @' + ns.n6 + ' ' + cfg._nft_rule_params + ' goto ' + nft_prefix + '_mark_' + mark);
			}
			break;
		case 'mac':
			nft4('add set inet ' + nft_table + ' ' + ns.n4 + ' { type ether_addr;' + cfg._nft_set_params + ' comment "' + comment + '"; }');
			v4_ok = true;
			nft6('add set inet ' + nft_table + ' ' + ns.n6 + ' { type ether_addr;' + cfg._nft_set_params + ' comment "' + comment + '"; }');
			v6_ok = true;
			nft4('add rule inet ' + nft_table + ' ' + nft_prefix + '_prerouting ether saddr @' + ns.n4 + ' ' + cfg._nft_rule_params + ' goto ' + nft_prefix + '_mark_' + mark);
			nft6('add rule inet ' + nft_table + ' ' + nft_prefix + '_prerouting ether saddr @' + ns.n6 + ' ' + cfg._nft_rule_params + ' goto ' + nft_prefix + '_mark_' + mark);
			break;
		}
		return _nftset_result(v4_ok, v6_ok);
	};

	nftset.destroy = function(iface, target, type_val, uid) {
		let ns = _nftset_names(iface, target, type_val, uid);
		if (!ns) return false;
		let nft_table = pkg.nft_table;
		let v4_ok = false, v6_ok = false;
		if (nft_call('delete', 'set', 'inet', nft_table, ns.n4)) v4_ok = true;
		if (nft_call('delete', 'set', 'inet', nft_table, ns.n6)) v6_ok = true;
		return _nftset_result(v4_ok, v6_ok);
	};

	nftset.destroy_user = function(iface, target, type_val, uid, mark) {
		let ns = _nftset_names(iface, target, type_val, uid);
		if (!ns) return false;
		let nft_prefix = pkg.nft_prefix;
		let nft_table = pkg.nft_table;
		let v4_ok = false, v6_ok = false;
		if (nft_call('delete', 'set', 'inet', nft_table, ns.n4)) v4_ok = true;
		if (nft_call('delete', 'set', 'inet', nft_table, ns.n6)) v6_ok = true;
		switch (ns.type_val) {
		case 'ip':
		case 'net':
			if (ns.target == 'dst') {
				nft_call('delete', 'rule', 'inet', nft_table, nft_prefix + '_prerouting', pkg.nft_ipv4_flag, 'daddr', '@' + ns.n4, 'goto', nft_prefix + '_mark_' + mark);
				v4_ok = true;
				nft_call('delete', 'rule', 'inet', nft_table, nft_prefix + '_prerouting', pkg.nft_ipv6_flag, 'daddr', '@' + ns.n6, 'goto', nft_prefix + '_mark_' + mark);
				v6_ok = true;
			} else if (ns.target == 'src') {
				nft_call('delete', 'rule', 'inet', nft_table, nft_prefix + '_prerouting', pkg.nft_ipv4_flag, 'saddr', '@' + ns.n4, 'goto', nft_prefix + '_mark_' + mark);
				v4_ok = true;
				nft_call('delete', 'rule', 'inet', nft_table, nft_prefix + '_prerouting', pkg.nft_ipv6_flag, 'saddr', '@' + ns.n6, 'goto', nft_prefix + '_mark_' + mark);
				v6_ok = true;
			}
			break;
		case 'mac':
			nft_call('delete', 'rule', 'inet', nft_table, nft_prefix + '_prerouting', 'ether', 'saddr', '@' + ns.n4, 'goto', nft_prefix + '_mark_' + mark);
			v4_ok = true;
			nft_call('delete', 'rule', 'inet', nft_table, nft_prefix + '_prerouting', 'ether', 'saddr', '@' + ns.n6, 'goto', nft_prefix + '_mark_' + mark);
			v6_ok = true;
			break;
		}
		return _nftset_result(v4_ok, v6_ok);
	};

	nftset.flush = function(iface, target, type_val, uid) {
		let ns = _nftset_names(iface, target, type_val, uid);
		if (!ns) return false;
		let nft_table = pkg.nft_table;
		let v4_ok = false, v6_ok = false;
		if (nft_call('flush', 'set', 'inet', nft_table, ns.n4)) v4_ok = true;
		if (nft_call('flush', 'set', 'inet', nft_table, ns.n6)) v6_ok = true;
		return _nftset_result(v4_ok, v6_ok);
	};


	// ── cleanup ───────────────────────────────────────────────────────

	function cleanup(...actions) {
		for (let action in actions) {
			switch (action) {
			case 'rt_tables': {
				let content = readfile(pkg.rt_tables_file) || '';
				let lines = split(content, '\n');
				let new_lines = [];
				for (let line in lines) {
					if (line == '') continue;
					let m = match(line, regexp(pkg.ip_table_prefix + '_(.*)'));
					if (m) {
						let table_name = pkg.ip_table_prefix + '_' + m[1];
						if (!network.is_netifd_table(table_name))
							continue;
					}
					push(new_lines, line);
				}
				writefile(pkg.rt_tables_file, join('\n', new_lines) + '\n');
				sh.run('sync');
				break;
			}
			case 'main_table': {
				let mask_val = hex(cfg.fw_mask);
				let mark_val = hex(cfg.uplink_mark);
				let max_ifaces = mask_val / mark_val;
				let prio_max = int(cfg.uplink_ip_rules_priority) + 1;
				let prio_min = int(cfg.uplink_ip_rules_priority) - max_ifaces;

				let rules4 = sh.exec(pkg.ip_full + ' -4 rule show 2>/dev/null');
				if (rules4) {
					let rule_lines = split(rules4, '\n');
					for (let line in rule_lines) {
						let m = match(line, /^(\d+):/);
						if (!m) continue;
						let prio = +m[1];
						if (prio < prio_min || prio > prio_max) continue;
						if (index(line, 'fwmark') >= 0 && index(line, 'lookup ' + pkg.ip_table_prefix + '_') >= 0) {
							let tm = match(line, /lookup\s+(\S+)/);
							if (tm && network.is_netifd_table(tm[1])) continue;
						}
						system(pkg.ip_full + ' -4 rule del priority ' + prio + ' 2>/dev/null');
					}
				}
				system(pkg.ip_full + ' -4 rule del lookup main suppress_prefixlength ' + cfg.prefixlength + ' 2>/dev/null');

				let rules6 = sh.exec(pkg.ip_full + ' -6 rule show 2>/dev/null');
				if (rules6) {
					let rule_lines6 = split(rules6, '\n');
					for (let line in rule_lines6) {
						let m = match(line, /^(\d+):/);
						if (!m) continue;
						let prio = +m[1];
						if (prio < prio_min || prio > prio_max) continue;
						if (index(line, 'fwmark') >= 0 && index(line, 'lookup ' + pkg.ip_table_prefix + '_') >= 0) {
							let tm = match(line, /lookup\s+(\S+)/);
							if (tm && network.is_netifd_table(tm[1])) continue;
						}
						system(pkg.ip_full + ' -6 rule del priority ' + prio + ' 2>/dev/null');
					}
				}
				system(pkg.ip_full + ' -6 rule del lookup main suppress_prefixlength ' + cfg.prefixlength + ' 2>/dev/null');
				break;
			}
			case 'main_chains': {
				let chains = split(pkg.chains_list, ' ');
				for (let c in [...chains, 'dstnat']) {
					c = lc(c);
					nft_call('flush', 'chain', 'inet', pkg.nft_table, c);
				}
				break;
			}
			case 'marking_chains': {
				let mark_chains = get_mark_nft_chains();
				if (mark_chains) {
					let external = get_external_mark_chains();
					let mc_list = split(mark_chains, ' ');
					for (let mc in mc_list) {
						mc = trim(mc);
						if (mc && !external[mc])
							nft_call('delete', 'chain', 'inet', pkg.nft_table, mc);
					}
				}
				break;
			}
			case 'sets': {
				let nft_sets_str = get_nft_sets();
				if (nft_sets_str) {
					let sets_list = split(nft_sets_str, '\n');
					for (let s in sets_list) {
						s = trim(s);
						if (s)
							nft_call('delete', 'set', 'inet', pkg.nft_table, s);
					}
				}
				break;
			}
			}
		}
		return true;
	}

	// ── resolver ──────────────────────────────────────────────────────

	resolver._uci_has_changes = function(conf) {
		return length(config.uci_ctx(conf).changes(conf) || []) > 0;
	};

	resolver._uci_add_list_if_new = function(conf, section, option, val) {
		if (!conf || !section || !option || !val) return false;
		let ctx = config.uci_ctx(conf);
		let current = ctx.get(conf, section, option);
		if (type(current) == 'array' && index(current, val) >= 0) return true;
		if (current == val) return true;
		ctx.list_append(conf, section, option, val);
		ctx.save(conf);
		return true;
	};

	resolver._dnsmasq_get_confdir = function(instance) {
		let ctx = config.uci_ctx('dhcp');
		let dhcp_cfg = ctx.get('dhcp', instance) ? instance : null;
		if (!dhcp_cfg) {
			ctx.foreach('dhcp', 'dnsmasq', function(s) {
				if (s['.name'] == instance || s['.index'] == instance)
					dhcp_cfg = s['.name'];
			});
		}
		if (!dnsmasq_ubus)
			dnsmasq_ubus = config.ubus_call('service', 'list', { name: 'dnsmasq' });
		let cfg_file = null;
		if (dnsmasq_ubus?.dnsmasq?.instances?.[dhcp_cfg]?.command) {
			let cmd_parts = dnsmasq_ubus.dnsmasq.instances[dhcp_cfg].command;
			if (type(cmd_parts) == 'array') {
				for (let i = 0; i < length(cmd_parts); i++) {
					if (cmd_parts[i] == '-C' && i + 1 < length(cmd_parts)) {
						cfg_file = cmd_parts[i + 1];
						break;
					}
				}
			}
		}
		if (!cfg_file) return null;
		let content = readfile(cfg_file) || '';
		let m = match(content, /(^|\n)conf-dir=([^\n]*)/);
		return m ? m[2] : null;
	};

	resolver._dnsmasq_instance_cleanup = function(instance) {
		if (!stat('/etc/config/dhcp')?.type) return true;
		let ctx = config.uci_ctx('dhcp');
		if (!ctx.get('dhcp', instance)) return false;
		let confdir = resolver._dnsmasq_get_confdir(instance);
		if (confdir) unlink(confdir + '/' + pkg.name);
		let current = ctx.get('dhcp', instance, 'addnmount');
		if (type(current) == 'array') {
			let idx = index(current, pkg.dnsmasq_file);
			if (idx >= 0) {
				ctx.reorder('dhcp', instance, idx);
				ctx.delete('dhcp', instance, 'addnmount', pkg.dnsmasq_file);
				ctx.save('dhcp');
			}
		}
		return true;
	};

	resolver._dnsmasq_instance_setup = function(instance) {
		if (!stat('/etc/config/dhcp')?.type) return true;
		let ctx = config.uci_ctx('dhcp');
		if (!ctx.get('dhcp', instance)) return false;
		resolver._uci_add_list_if_new('dhcp', instance, 'addnmount', pkg.dnsmasq_file);
		let confdir = resolver._dnsmasq_get_confdir(instance);
		if (!confdir) return false;
		sh.run('ln -sf ' + sh.quote(pkg.dnsmasq_file) + ' ' + sh.quote(confdir + '/' + pkg.name));
		sh.run('chmod 660 ' + sh.quote(confdir + '/' + pkg.name));
		sh.run('chown -h root:dnsmasq ' + sh.quote(confdir + '/' + pkg.name));
		return true;
	};

	resolver.check_support = function() {
		switch (cfg.resolver_set) {
		case '':
		case 'none':
			return true;
		case 'dnsmasq.nftset':
			return env.resolver_set_supported;
		case 'unbound.nftset':
			return true;
		}
		return false;
	};

	resolver.wait = function(timeout) {
		switch (cfg.resolver_set) {
		case '':
		case 'none':
		case 'dnsmasq.nftset': {
			if (resolver_working_flag) return true;
			let t = +(timeout || '30');
			let hostname = config.uci_ctx('system').get('system', '@system[0]', 'hostname') || 'OpenWrt';
			for (let count = 0; count < t; count++) {
				if (sh.run('resolveip ' + sh.quote(hostname)) == 0) {
					resolver_working_flag = true;
					return true;
				}
				system('sleep 1');
			}
			return false;
		}
		case 'unbound.nftset':
			return true;
		}
		return true;
	};

	resolver.kill = function() {
		switch (cfg.resolver_set) {
		case '':
		case 'none':
			return true;
		case 'dnsmasq.nftset':
			if (env.resolver_set_supported)
				sh.run('killall -q -s HUP dnsmasq');
			return true;
		case 'unbound.nftset':
			return true;
		}
		return true;
	};

	resolver.reload = function() {
		switch (cfg.resolver_set) {
		case '':
		case 'none':
			return true;
		case 'dnsmasq.nftset':
			if (!env.resolver_set_supported) return false;
			output.info.write('Reloading dnsmasq ');
			output.verbose.write('Reloading dnsmasq ');
			if (sh.run('/etc/init.d/dnsmasq reload') == 0) {
				output.okn();
				return true;
			}
			output.failn();
			return false;
		case 'unbound.nftset':
			return true;
		}
		return true;
	};

	resolver.restart = function() {
		switch (cfg.resolver_set) {
		case '':
		case 'none':
			return true;
		case 'dnsmasq.nftset':
			if (!env.resolver_set_supported) return false;
			output.info.write('Restarting dnsmasq ');
			output.verbose.write('Restarting dnsmasq ');
			if (sh.run('/etc/init.d/dnsmasq restart') == 0) {
				output.okn();
				return true;
			}
			output.failn();
			return false;
		case 'unbound.nftset':
			return true;
		}
		return true;
	};

	resolver.store_hash = function() {
		switch (cfg.resolver_set) {
		case '':
		case 'none':
			return true;
		case 'dnsmasq.nftset': {
			let s = stat(pkg.dnsmasq_file);
			if (s && s.size > 0) {
				let md5_out = sh.exec('md5sum ' + sh.quote(pkg.dnsmasq_file));
				let m = match(md5_out, /^(\S+)/);
				resolver_stored_hash = m ? m[1] : '';
			} else {
				resolver_stored_hash = '';
			}
			return true;
		}
		case 'unbound.nftset':
			return true;
		}
		return true;
	};

	resolver.compare_hash = function() {
		switch (cfg.resolver_set) {
		case '':
		case 'none':
			return false;
		case 'dnsmasq.nftset': {
			if (!env.resolver_set_supported) return false;
			if (resolver._uci_has_changes('dhcp')) {
				config.uci_ctx('dhcp').commit('dhcp');
			}
			let resolver_new_hash = '';
			let s = stat(pkg.dnsmasq_file);
			if (s && s.size > 0) {
				let md5_out = sh.exec('md5sum ' + sh.quote(pkg.dnsmasq_file));
				let m = match(md5_out, /^(\S+)/);
				resolver_new_hash = m ? m[1] : '';
			}
			return resolver_new_hash != resolver_stored_hash;
		}
		case 'unbound.nftset':
			return false;
		}
		return false;
	};

	resolver.configure = function() {
		switch (cfg.resolver_set) {
		case '':
		case 'none':
			return true;
		case 'dnsmasq.nftset': {
			if (!env.resolver_set_supported) return false;
			unlink(pkg.dnsmasq_file);
			writefile(pkg.dnsmasq_file, '');
			let ctx2 = config.uci_ctx('dhcp', true);
			if (cfg.resolver_instance == '*') {
				ctx2.foreach('dhcp', 'dnsmasq', function(s) {
					resolver._dnsmasq_instance_setup(s['.name']);
				});
			} else {
				ctx2.foreach('dhcp', 'dnsmasq', function(s) {
					resolver._dnsmasq_instance_cleanup(s['.name']);
				});
				let instances = split(trim(cfg.resolver_instance), /\s+/);
				for (let inst in instances) {
					if (!resolver._dnsmasq_instance_setup('@dnsmasq[' + inst + ']'))
						resolver._dnsmasq_instance_setup(inst);
				}
			}
			return true;
		}
		case 'unbound.nftset':
			return true;
		}
		return true;
	};

	resolver.cleanup = function() {
		switch (cfg.resolver_set) {
		case '':
		case 'none':
			return true;
		case 'dnsmasq.nftset': {
			if (!env.resolver_set_supported) return false;
			unlink(pkg.dnsmasq_file);
			let ctx_dhcp = config.uci_ctx('dhcp', true);
			ctx_dhcp.foreach('dhcp', 'dnsmasq', function(s) {
				resolver._dnsmasq_instance_cleanup(s['.name']);
			});
			return true;
		}
		case 'unbound.nftset':
			return true;
		}
		return true;
	};

	resolver.create_set = function(iface, target, type_val, uid, name) {
		switch (cfg.resolver_set) {
		case '':
		case 'none':
			return false;
		case 'dnsmasq.nftset':
			if (!env.resolver_set_supported) return false;
			if (target == 'src') return false;
			return nftset.create_dnsmasq(iface, target, type_val, uid, name);
		case 'unbound.nftset':
			return false;
		}
		return false;
	};

	resolver.add_element = function(iface, target, type_val, uid, name, value) {
		switch (cfg.resolver_set) {
		case '':
		case 'none':
			return false;
		case 'dnsmasq.nftset': {
			if (!env.resolver_set_supported) return false;
			if (target == 'src') return false;
			let words = split(trim('' + (value || '')), /\s+/);
			for (let d in words) {
				nftset.add_dnsmasq_element(iface, target, type_val, uid, name, d);
			}
			return true;
		}
		case 'unbound.nftset':
			return false;
		}
		return false;
	};

	// ── Address Classification ────────────────────────────────────────

	function classify_addr(value, direction, iface, uid, name, use_resolver) {
		let negation = '', nftset_suffix = '';
		if (substr(value, 0, 1) == '!') {
			negation = '!= ';
			value = replace(value, /!/g, '');
			nftset_suffix = '_neg';
		}
		let first_val = V.str_first_word(value);
		let param4 = '', param6 = '';
		let empty4 = false, empty6 = false;

		let ifname_key = (direction == 'src') ? 'iifname' : 'oifname';
		let addr_dir = (direction == 'src') ? 'saddr' : 'daddr';
		let target = (direction == 'src') ? 'src' : 'dst';

		if (V.is_phys_dev(first_val)) {
			param4 = ifname_key + ' ' + negation + '{ ' + V.inline_set(value) + ' }';
			param6 = param4;
		} else if (direction == 'src' && V.is_mac_address(first_val)) {
			param4 = 'ether saddr ' + negation + '{ ' + V.inline_set(value) + ' }';
			param6 = param4;
		} else if (V.is_domain(first_val)) {
			if (use_resolver && iface &&
				resolver.create_set(iface, target, 'ip', uid, name) &&
				resolver.add_element(iface, target, 'ip', uid, name, value)) {
				let nft_pfx = pkg.nft_prefix;
				param4 = pkg.nft_ipv4_flag + ' ' + addr_dir + ' ' + negation +
					'@' + nft_pfx + '_' + iface + '_4_' + target + '_ip_' + uid + nftset_suffix;
				param6 = pkg.nft_ipv6_flag + ' ' + addr_dir + ' ' + negation +
					'@' + nft_pfx + '_' + iface + '_6_' + target + '_ip_' + uid + nftset_suffix;
			} else {
				let is4 = '', is6 = '';
				for (let d in split(value, /\s+/)) {
					if (!d) continue;
					let r4 = resolveip_to_nftset4(d);
					let r6 = resolveip_to_nftset6(d);
					if (!r4 && !r6) {
						push(state.errors, { code: 'errorFailedToResolve', info: d });
					} else {
						if (r4) is4 += (is4 ? ', ' : '') + r4;
						if (r6) is6 += (is6 ? ', ' : '') + r6;
					}
				}
				if (!is4) empty4 = true;
				if (!is6) empty6 = true;
				param4 = pkg.nft_ipv4_flag + ' ' + addr_dir + ' ' + negation + '{ ' + is4 + ' }';
				param6 = pkg.nft_ipv6_flag + ' ' + addr_dir + ' ' + negation + '{ ' + is6 + ' }';
			}
		} else {
			let is4 = '', is6 = '';
			for (let v in split(value, /\s+/)) {
				if (!v) continue;
				let clean = replace(v, /^!/, '');
				if (V.is_ipv4(clean)) is4 += (is4 ? ' ' : '') + v;
				else is6 += (is6 ? ' ' : '') + v;
			}
			if (!is4) empty4 = true;
			if (!is6) empty6 = true;
			param4 = pkg.nft_ipv4_flag + ' ' + addr_dir + ' ' + negation + '{ ' + V.inline_set(is4) + ' }';
			param6 = pkg.nft_ipv6_flag + ' ' + addr_dir + ' ' + negation + '{ ' + V.inline_set(is6) + ' }';
		}

		return { param4, param6, empty4, empty6 };
	}

	return {
		get_rt_tables_id, get_rt_tables_next_id, get_rt_tables_non_pbr_next_id,
		get_mark_nft_chains, get_external_mark_chains,
		is_service_running_nft, get_nft_sets,
		resolveip_to_nftset, resolveip_to_nftset4, resolveip_to_nftset6,
		ipv4_leases_to_nftset, ipv6_leases_to_nftset,
		nft_add, nft4, nft6, nft_call, nft_check_element,
		ensure_mark_chain,
		nft_file,
		get_set_name, nftset,
		cleanup,
		resolver,
		classify_addr,
	};
}

export default create_nft;
