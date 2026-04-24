'use strict';
// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright 2020-2026 MOSSDeF, Stan Grishin (stangri@melmac.ca).
//
// Package constants, output symbols, and error/warning message catalog.

// ── Constants ───────────────────────────────────────────────────────

const pkg = {
	name: 'pbr',
	version: 'dev-test',
	compat: '31',
	config_file: '/etc/config/pbr',
	debug_file: '/var/run/pbr.debug',
	lock_file: '/var/run/pbr.lock',
	dnsmasq_file: '/var/run/pbr.dnsmasq',
	mwan4_nft_prefix: 'mwan4',
	mwan4_nft_iface_file: '/usr/share/nftables.d/ruleset-post/12-mwan4-interfaces.nft',
	nft_temp_file: '/var/run/pbr.nft',
	nft_netifd_file: '/usr/share/nftables.d/ruleset-post/20-pbr-netifd.nft',
	nft_main_file: '/usr/share/nftables.d/ruleset-post/30-pbr.nft',
	nft_table: 'fw4',
	nft_prefix: 'pbr',
	nft_ipv4_flag: 'ip',
	nft_ipv6_flag: 'ip6',
	chains_list: 'forward output prerouting',
	ip_full: '/usr/libexec/ip-full',
	ip_table_prefix: 'pbr',
	rt_tables_file: '/etc/iproute2/rt_tables',
	ss_config_file: '/etc/shadowsocks',
	tor_config_file: '/etc/tor/torrc',
	xray_iface_prefix: 'xray_',
	url: function(fragment) {
		return sprintf("https://docs.openwrt.melmac.ca/%s/%s/%s", this.name, split(this.version, '-')[0], fragment || '');
	},
};
pkg.service_name = pkg.name + ' ' + pkg.version;

// ── Symbols ─────────────────────────────────────────────────────────

const sym = {
	dot:  ['.', '[w]'],
	ok:   ['\033[0;32m✓\033[0m', '\033[0;32m[✓]\033[0m'],
	okb:  ['\033[1;34m✓\033[0m', '\033[1;34m[✓]\033[0m'],
	fail: ['\033[0;31m✗\033[0m', '\033[0;31m[✗]\033[0m'],
	ERR:  '\033[0;31mERROR:\033[0m',
	WARN: '\033[0;33mWARNING:\033[0m',
};

// ── Error/Warning Message Catalog ───────────────────────────────────

function get_text(code, cfg, ...args) {
	let a1 = length(args) > 0 ? args[0] : '';
	let texts = {
		errorConfigValidation:                 sprintf("Config (%s) validation failure", pkg.config_file),
		errorNoNft:                            sprintf("Resolver set support (%s) requires nftables, but nft binary cannot be found", cfg.resolver_set),
		errorResolverNotSupported:             sprintf("Resolver set (%s) is not supported on this system", cfg.resolver_set),
		errorServiceDisabled:                  sprintf("The %s service is currently disabled", pkg.name),
		errorNoUplinkGateway:                  sprintf("The %s service failed to discover uplink gateway", pkg.service_name),
		errorNoUplinkInterface:                sprintf("The %s interface not found, you need to set the 'pbr.config.uplink_interface' option", a1),
		errorNoUplinkInterfaceHint:            sprintf("Refer to %s", a1),
		errorNftsetNameTooLong:                sprintf("The nft set name '%s' is longer than allowed 255 characters", a1),
		errorUnexpectedExit:                   sprintf("Unexpected exit or service termination: '%s'", a1),
		errorPolicyNoSrcDest:                  sprintf("Policy '%s' has no source/destination parameters", a1),
		errorPolicyNoInterface:                sprintf("Policy '%s' has no assigned interface", a1),
		errorPolicyNoDns:                      sprintf("Policy '%s' has no assigned DNS", a1),
		errorPolicyProcessNoInterfaceDns:      sprintf("Interface '%s' has no assigned DNS", a1),
		errorPolicyUnknownInterface:           sprintf("Policy '%s' has an unknown interface", a1),
		errorPolicyProcessCMD:                 sprintf("'%s'", a1),
		errorFailedSetup:                      sprintf("Failed to set up '%s'", a1),
		errorFailedReload:                     sprintf("Failed to reload '%s'", a1),
		errorUserFileNotFound:                 sprintf("Custom user file '%s' not found or empty", a1),
		errorUserFileSyntax:                   sprintf("Syntax error in custom user file '%s'", a1),
		errorUserFileRunning:                  sprintf("Error running custom user file '%s'", a1),
		errorUserFileNoCurl:                   sprintf("Use of 'curl' is detected in custom user file '%s', but 'curl' isn't installed", a1),
		errorNoGateways:                       "Failed to set up any gateway",
		errorResolver:                         sprintf("Resolver '%s'", a1),
		errorPolicyProcessNoIpv6:              sprintf("Skipping IPv6 policy '%s' as IPv6 support is disabled", a1),
		errorPolicyProcessUnknownFwmark:       sprintf("Unknown packet mark for interface '%s'", a1),
		errorPolicyProcessMismatchFamily:      sprintf("Mismatched IP family between in policy '%s'", a1),
		errorPolicyProcessUnknownProtocol:     sprintf("Unknown protocol in policy '%s'", a1),
		errorPolicyProcessInsertionFailed:     sprintf("Insertion failed for both IPv4 and IPv6 for policy '%s'", a1),
		errorPolicyProcessInsertionFailedIpv4: sprintf("Insertion failed for IPv4 for policy '%s'", a1),
		errorPolicyProcessUnknownEntry:        sprintf("Unknown entry in policy '%s'", a1),
		errorInterfaceRoutingEmptyValues:      "Received empty tid/mark or interface name when setting up routing",
		errorInterfaceMarkOverflow:            sprintf("Interface mark for '%s' exceeds the fwmask value", a1),
		errorFailedToResolve:                  sprintf("Failed to resolve '%s'", a1),
		errorInvalidOVPNConfig:                sprintf("Invalid OpenVPN config for '%s' interface", a1),
		errorNftMainFileInstall:               sprintf("Failed to install fw4 nft file '%s'", a1),
		errorTryFailed:                        sprintf("Command failed: %s", a1),
		errorDownloadUrlNoHttps:               sprintf("Failed to download '%s', HTTPS is not supported", a1),
		errorDownloadUrl:                      sprintf("Failed to download '%s'", a1),
		errorNoDownloadWithSecureReload:       sprintf("Policy '%s' refers to URL which can't be downloaded in 'secure_reload' mode", a1),
		errorFileSchemaRequiresCurl:           "The file:// schema requires curl, but it's not detected on this system",
		errorIncompatibleUserFile:             sprintf("Incompatible custom user file detected '%s'", a1),
		errorUserFileUnsafeNft:                sprintf("Unsafe nft command in custom user file '%s'; only 'add', 'insert' and 'create' are allowed", a1),
		errorDefaultFw4TableMissing:           sprintf("Default fw4 table '%s' is missing", a1),
		errorDefaultFw4ChainMissing:           sprintf("Default fw4 chain '%s' is missing", a1),
		errorRequiredBinaryMissing:            sprintf("Required binary '%s' is missing", a1),
		errorInterfaceRoutingUnknownDevType:   sprintf("Unknown IPv6 Link type for device '%s'", a1),
		errorUplinkDown:                       "Uplink/WAN interface is still down, increase value of 'procd_boot_trigger_delay' option",
		errorMktempFileCreate:                 sprintf("Failed to create temporary file with mktemp mask: '%s'", a1),
		errorSummary:                          sprintf("Errors encountered, please check %s", a1),
		errorNftNetifdFileInstall:             sprintf("Netifd setup: failed to install fw4 netifd nft file '%s'", a1),
		errorNftNetifdFileDelete:              sprintf("Netifd setup: failed to remove fw4 netifd nft file '%s'", a1),
		errorNetifdMissingOption:              sprintf("Netifd setup: required option '%s' is missing", a1),
		errorNetifdInvalidGateway4:            sprintf("Netifd setup: invalid value of netifd_interface_default option '%s'", a1),
		errorNetifdInvalidGateway6:            sprintf("Netifd setup: invalid value of netifd_interface_default6 option '%s'", a1),
		warningInvalidOVPNConfig:              sprintf("Invalid OpenVPN config for '%s' interface", a1),
		warningResolverNotSupported:           sprintf("Resolver set (%s) is not supported on this system", cfg.resolver_set),
		warningPolicyProcessCMD:               sprintf("'%s'", a1),
		warningTorUnsetParams:                 sprintf("Please unset 'src_addr', 'src_port' and 'dest_port' for policy '%s'", a1),
		warningTorUnsetProto:                  sprintf("Please unset 'proto' or set 'proto' to 'all' for policy '%s'", a1),
		warningTorUnsetChainNft:               sprintf("Please unset 'chain' or set 'chain' to 'prerouting' for policy '%s'", a1),
		warningOutdatedLuciPackage:            sprintf("The WebUI application is outdated (version %s), please update it", a1),
		warningDnsmasqInstanceNoConfdir:       sprintf("Dnsmasq instance '%s' targeted in settings, but it doesn't have its own confdir", a1),
		warningDhcpLanForce:                   sprintf("Please set 'dhcp.%s.force=1' to speed up service start-up", a1),
		warningSummary:                        sprintf("Warnings encountered, please check %s", pkg.url('#warning-messages-details')),
		warningIncompatibleDHCPOption6:        sprintf("Incompatible DHCP Option 6 for interface '%s'", a1),
		warningNetifdMissingInterfaceLocal:    sprintf("Netifd setup: option netifd_interface_local is missing, assuming '%s'", a1),
		warningUplinkDown:                     "Uplink/WAN interface is still down, going back to boot mode",
		warningDynamicRoutingMode:             sprintf("Running in dynamic routing tables mode. Consider installing netifd extensions ('pbr netifd install') or mwan4 for more efficient operation. See %s", pkg.url('#routing-tables-modes')),
	};
	return texts[code] || sprintf("Unknown error/warning '%s'", code);
}

export default { pkg, sym, get_text };
