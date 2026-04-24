'use strict';
// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright 2020-2026 MOSSDeF, Stan Grishin (stangri@melmac.ca).
//
// Pure validation functions. Optionally receives stat() for is_phys_dev.

function create_validators(stat_fn) {

function str_contains(haystack, needle) { return haystack != null && needle != null && index('' + haystack, '' + needle) >= 0; }
function str_contains_word(haystack, needle) { return !!(haystack && needle) && index(split(trim('' + haystack), /\s+/), '' + needle) >= 0; }
function str_first_word(s) { let m = s ? match(trim('' + s), /^(\S+)/) : null; return m ? m[1] : ''; }

function is_ipv4(s) {
	if (!s) return false;
	return !!match('' + s, /^((25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(\/([0-2]?[0-9]|3[0-2]))?$/);
}

function is_mac_address(s) {
	if (!s) return false;
	return !!match('' + s, /^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$/);
}

function is_ipv6(s) {
	if (!s) return false;
	s = '' + s;
	if (is_mac_address(s)) return false;
	return index(s, ':') >= 0;
}

function is_domain(s) {
	if (!s) return false;
	s = '' + s;
	if (is_ipv4(s)) return false;
	if (match(s, /^([0-9A-Fa-f]{2}-){5}([0-9A-Fa-f]{2})$/)) return false;
	return !!match(s, /^[a-zA-Z0-9]$/) || !!match(s, /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,61}[a-zA-Z0-9]$/) ||
		!!match(s, /^([a-zA-Z0-9]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/);
}

function is_phys_dev(s) {
	if (!s) return false;
	s = '' + s;
	if (substr(s, 0, 1) != '@') return false;
	if (!stat_fn) return false;
	let dev = substr(s, 1);
	return stat_fn('/sys/class/net/' + dev)?.type == 'link'; // ucode-lsp disable
}

function is_url_file(s) { return !!s && substr('' + s, 0, 7) == 'file://'; }
function is_url_https(s) { return !!s && substr('' + s, 0, 8) == 'https://'; }
function is_url(s) { if (!s) return false; s = '' + s; return is_url_file(s) || substr(s, 0, 6) == 'ftp://' || substr(s, 0, 7) == 'http://' || is_url_https(s); }

function is_family_mismatch(a, b) {
	a = replace('' + (a || ''), '!', '');
	b = replace('' + (b || ''), '!', '');
	return (is_ipv4(a) && is_ipv6(b)) || (is_ipv6(a) && is_ipv4(b));
}

function filter_options(opt, values) {
	if (!values) return '';
	let parts = split(trim('' + values), /\s+/);
	let ret = [];
	for (let v in parts) {
		if (str_contains(opt, '_negative')) {
			if (substr('' + v, 0, 1) != '!') continue;
			opt = replace(opt, '_negative', '');
		}
		let check_val = replace(v, '!', '');
		let ok = false;
		switch (opt) {
		case 'phys_dev': ok = is_phys_dev(check_val); break;
		case 'mac_address': ok = is_mac_address(check_val); break;
		case 'domain': ok = is_domain(check_val); break;
		case 'ipv4': ok = is_ipv4(check_val); break;
		case 'ipv6': ok = is_ipv6(check_val); break;
		}
		if (ok) push(ret, v);
	}
	return join(' ', ret);
}

function inline_set(value) {
	if (!value) return '';
	let parts = split(trim('' + value), /\s+/);
	let result = [];
	for (let i in parts) {
		let cleaned = replace(i, /^[@!]/, '');
		push(result, cleaned);
	}
	return join(', ', result);
}

return {
	str_contains,
	str_contains_word,
	str_first_word,
	is_ipv4,
	is_ipv6,
	is_mac_address,
	is_domain,
	is_phys_dev,
	is_url_file,
	is_url_https,
	is_url,
	is_family_mismatch,
	filter_options,
	inline_set,
};

}

export default create_validators;
