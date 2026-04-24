'use strict';
// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright 2020-2026 MOSSDeF, Stan Grishin (stangri@melmac.ca).
//
// System interaction wrappers: shell execution, directory creation,
// ip command wrapper with rule-replace emulation.

function create_sys(fs_mod, pkg) {
	let popen = fs_mod.popen;
	let stat = fs_mod.stat;
	let access = fs_mod.access;
	let _dirname = fs_mod.dirname;
	let _mkdir = fs_mod.mkdir;

	function quote(s) {
		return "'" + replace('' + s, "'", "'\\''") + "'";
	}

	function exec(cmd) {
		let p = popen(cmd, 'r');
		if (!p) return '';
		let data = p.read('all') || '';
		p.close();
		return trim(data);
	}

	function run(cmd) {
		return system(cmd + ' >/dev/null 2>&1');
	}

	function mkdir_p(path) {
		if (!path || stat(path)?.type == 'directory') return true;
		let parent = _dirname(path);
		if (parent && parent != path) mkdir_p(parent);
		return _mkdir(path) != null;
	}

	function is_present(cmd) {
		if (index(cmd, '/') >= 0)
			return access(cmd, 'x') == true;
		for (let dir in ['/usr/sbin', '/usr/bin', '/sbin', '/bin'])
			if (access(dir + '/' + cmd, 'x') == true) return true;
		return false;
	}

	function ip(...args) {
		if (length(args) < 1) return 1;
		let fam = args[0];
		if (fam == '-4' || fam == '-6') {
			let rest = slice(args, 1);
			if (length(rest) >= 2 && rest[0] == 'rule' && rest[1] == 'replace') {
				let rule_args = slice(rest, 2);
				let prio = null;
				let newargs = [];
				for (let i = 0; i < length(rule_args); i++) {
					if (rule_args[i] == 'priority' || rule_args[i] == 'pref') {
						i++;
						if (i < length(rule_args))
							prio = rule_args[i];
						continue;
					}
					push(newargs, rule_args[i]);
				}
				if (prio != null) {
					system(pkg.ip_full + ' ' + fam + ' rule del priority ' + prio + ' 2>/dev/null');
					return system(pkg.ip_full + ' ' + fam + ' rule add ' + join(' ', newargs) + ' pref ' + prio);
				}
				return system(pkg.ip_full + ' ' + fam + ' rule add ' + join(' ', newargs));
			}
			return system(pkg.ip_full + ' ' + fam + ' ' + join(' ', rest));
		}
		return system(pkg.ip_full + ' ' + join(' ', args));
	}

	function try_cmd(errors, ...args) {
		let cmd = join(' ', args);
		if (run(cmd) != 0) {
			push(errors, { code: 'errorTryFailed', info: cmd });
			return false;
		}
		return true;
	}

	function try_ip(errors, ...args) {
		if (ip(...args) != 0) {
			push(errors, { code: 'errorTryFailed', info: pkg.ip_full + ' ' + join(' ', args) });
			return false;
		}
		return true;
	}

	return { quote, exec, run, mkdir_p, is_present, ip, try_cmd, try_ip };
}

export default create_sys;
