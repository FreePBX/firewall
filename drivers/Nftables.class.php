<?php
// vim: set ai ts=4 sw=4 ft=php:
namespace FreePBX\modules\Firewall\Drivers;

/**
 * Native nftables driver for FreePBX 18.
 *
 * Policy is materialized in the inet fpbx and ip fpbxnat tables. Legacy
 * iptables input is handled only by LegacyRulesMigrator.
 */
class Nftables {

	const FAMILY = 'inet';
	const TABLE = 'fpbx';
	const NAT_FAMILY = 'ip';
	const NAT_TABLE = 'fpbxnat';

	private $nft;
	private $cache = null;
	private $serviceZones = array();
	private $interfaceZones = array();
	private $hostZones = array();
	private $rejectServices = array();
	private $rfwRules = array();

	public function __construct() {
		$this->nft = $this->findNft();
	}

	public function l($str) {
		if (function_exists('fwLog')) {
			fwLog($str);
		} else {
			print "LOG: $str\n";
		}
	}

	public function getDriverName() {
		return 'Nftables';
	}

	private function findNft() {
		if (function_exists('fpbx_which')) {
			$path = fpbx_which('nft');
			if ($path) {
				return $path;
			}
		}
		foreach (array('/usr/sbin/nft', '/sbin/nft', '/usr/bin/nft') as $path) {
			if (is_executable($path)) {
				return $path;
			}
		}
		throw new \RuntimeException('nftables is required by the FreePBX Firewall');
	}

	public function ensureBaseRuleset() {
		$output = array();
		$status = 0;
		$this->nftExec('list table '.self::FAMILY.' '.self::TABLE, $output, $status);
		if ($status === 0 && $this->validateRunning()) {
			return true;
		}
		if ($status === 0) {
			$this->nftExec('delete table '.self::FAMILY.' '.self::TABLE, $output, $status);
		}
		$this->nftExec('list table '.self::NAT_FAMILY.' '.self::NAT_TABLE, $output, $status);
		if ($status === 0) {
			$this->nftExec('delete table '.self::NAT_FAMILY.' '.self::NAT_TABLE, $output, $status);
		}

		$script = <<<'NFT'
table inet fpbx {
	set blacklist { type ipv4_addr; flags interval; }
	set blacklist6 { type ipv6_addr; flags interval; }
	set registrations { type ipv4_addr; flags interval; }
	set registrations6 { type ipv6_addr; flags interval; }
	set smarthosts { type ipv4_addr; flags interval; }
	set smarthosts6 { type ipv6_addr; flags interval; }
	set nets-trusted { type ipv4_addr; flags interval; }
	set nets-internal { type ipv4_addr; flags interval; }
	set nets-other { type ipv4_addr; flags interval; }
	set nets-external { type ipv4_addr; flags interval; }
	set nets-trusted6 { type ipv6_addr; flags interval; }
	set nets-internal6 { type ipv6_addr; flags interval; }
	set nets-other6 { type ipv6_addr; flags interval; }
	set nets-external6 { type ipv6_addr; flags interval; }
	set rfw_whitelist { type ipv4_addr; flags timeout; timeout 90s; }
	set rfw_whitelist6 { type ipv6_addr; flags timeout; timeout 90s; }
	set rfw_attacker { type ipv4_addr; flags timeout; timeout 1d; }
	set rfw_attacker6 { type ipv6_addr; flags timeout; timeout 1d; }
	set rfw_clamped { type ipv4_addr; flags timeout; timeout 5m; }
	set rfw_clamped6 { type ipv6_addr; flags timeout; timeout 5m; }
	set rfw_tempwhitelist { type ipv4_addr; flags timeout; timeout 5m; }
	set rfw_tempwhitelist6 { type ipv6_addr; flags timeout; timeout 5m; }
	set rfw_discovered { type ipv4_addr; flags timeout; timeout 1d; }
	set rfw_discovered6 { type ipv6_addr; flags timeout; timeout 1d; }
	set le_ports { type inet_service; flags timeout; timeout 60s; }

	chain input {
		type filter hook input priority filter; policy accept;
		jump fpbxfirewall
	}
	chain forward {
		type filter hook forward priority filter; policy accept;
	}
	chain fpbxfirewall {
		iifname "lo" accept
		ct state established,related accept
		meta l4proto icmp accept
		meta l4proto ipv6-icmp accept
		jump fpbx-rtp
		jump fpbxblacklist
		jump fpbxsignalling
		jump fpbxsmarthosts
		jump fpbxregistrations
		jump fpbxnets
		jump fpbxhosts
		jump fpbxinterfaces
		jump fpbxreject
		meta mark and 0x2 == 0x2 jump fpbxrfw
		tcp dport @le_ports accept
		jump fpbxcustom
		jump fpbxlogdrop
	}
	chain fpbx-rtp {}
	chain fpbxsignalling {}
	chain fpbxsmarthosts {
		meta mark and 0x1 == 0x1 ip saddr @smarthosts accept
		meta mark and 0x1 == 0x1 ip6 saddr @smarthosts6 accept
	}
	chain fpbxregistrations {
		ip saddr @registrations jump fpbxknownreg
		ip6 saddr @registrations6 jump fpbxknownreg
	}
	chain fpbxknownreg {
		accept
	}
	chain fpbxblacklist {
		ip saddr @blacklist jump fpbxlogdrop
		ip6 saddr @blacklist6 jump fpbxlogdrop
	}
	chain fpbxnets {
		ip saddr @nets-trusted jump zone-trusted
		ip saddr @nets-internal jump zone-internal
		ip saddr @nets-other jump zone-other
		ip saddr @nets-external jump zone-external
		ip6 saddr @nets-trusted6 jump zone-trusted
		ip6 saddr @nets-internal6 jump zone-internal
		ip6 saddr @nets-other6 jump zone-other
		ip6 saddr @nets-external6 jump zone-external
	}
	chain fpbxhosts {}
	chain fpbxinterfaces {}
	chain fpbxreject {}
	chain fpbxrfw {
		ip saddr @rfw_whitelist accept
		ip6 saddr @rfw_whitelist6 accept
		ip saddr @rfw_tempwhitelist accept
		ip6 saddr @rfw_tempwhitelist6 accept
		ip saddr @rfw_attacker jump fpbxattacker
		ip6 saddr @rfw_attacker6 jump fpbxattacker
		ip saddr @rfw_clamped jump fpbxshortblock
		ip6 saddr @rfw_clamped6 jump fpbxshortblock
	}
	chain fpbxratelimit {}
	chain fpbxattacker {
		jump fpbxlogdrop
	}
	chain fpbxshortblock {
		jump fpbxlogdrop
	}
	chain fpbxcustom {}
	chain zone-trusted {
		accept
	}
	chain zone-internal {}
	chain zone-other {}
	chain zone-external {}
	chain zone-reject {
		jump fpbxlogdrop
	}
	chain fpbxlogdrop {
		log prefix "fpbx-drop: " flags all
		drop
	}
}
table ip fpbxnat {
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
	}
}
NFT;
		return $this->applyScript($script);
	}

	private function applyScript($script, $checkOnly = false) {
		$tmp = tempnam(sys_get_temp_dir(), 'fpbx-nft-');
		if ($tmp === false || file_put_contents($tmp, rtrim($script)."\n") === false) {
			throw new \RuntimeException('Unable to create temporary nftables rules file');
		}
		$check = escapeshellcmd($this->nft).' --check -f '.escapeshellarg($tmp).' 2>&1';
		exec($check, $output, $status);
		if ($status !== 0) {
			@unlink($tmp);
			$this->l('nft validation failed: '.implode("\n", $output));
			return false;
		}
		if ($checkOnly) {
			@unlink($tmp);
			return true;
		}
		$output = array();
		$cmd = escapeshellcmd($this->nft).' -f '.escapeshellarg($tmp).' 2>&1';
		$this->l($cmd);
		exec($cmd, $output, $status);
		@unlink($tmp);
		if ($status !== 0) {
			$this->l('nft apply failed: '.implode("\n", $output));
			return false;
		}
		$this->cache = null;
		return true;
	}

	private function nftExec($args, &$output = null, &$status = null) {
		$output = array();
		$status = 0;
		$cmd = escapeshellcmd($this->nft).' '.$args.' 2>&1';
		$this->l($cmd);
		exec($cmd, $output, $status);
		return $status;
	}

	public function validateRunning() {
		$output = array();
		$status = 0;
		$this->nftExec('list table '.self::FAMILY.' '.self::TABLE, $output, $status);
		if ($status !== 0) {
			return false;
		}
		$rules = implode("\n", $output);
		foreach (array(
			'fpbxfirewall', 'fpbx-rtp', 'fpbxsignalling', 'fpbxsmarthosts',
			'fpbxregistrations', 'fpbxnets', 'fpbxhosts', 'fpbxinterfaces',
			'fpbxreject', 'fpbxrfw', 'fpbxratelimit', 'fpbxattacker',
			'fpbxshortblock', 'fpbxknownreg', 'fpbxlogdrop', 'fpbxcustom',
			'zone-trusted', 'zone-internal', 'rfw_whitelist', 'rfw_attacker',
			'smarthosts', 'le_ports',
		) as $object) {
			if (strpos($rules, $object) === false) {
				$this->l("Missing native nftables object: $object");
				return false;
			}
		}
		return true;
	}

	public function refreshCache() {
		$this->cache = null;
		if (!$this->ensureBaseRuleset()) {
			return false;
		}
		return $this->getCurrentIptables();
	}

	public function commit() {
		$dir = '/var/lib/asterisk/firewall';
		if (!is_dir($dir) && !@mkdir($dir, 0750, true)) {
			return false;
		}
		$output = array();
		$status = 0;
		$this->nftExec('list table '.self::FAMILY.' '.self::TABLE, $output, $status);
		if ($status !== 0) {
			return false;
		}
		return file_put_contents(
			$dir.'/fpbx.nft',
			"#!/usr/sbin/nft -f\n".implode("\n", $output)."\n"
		) !== false;
	}

	public function getKnownNetworks() {
		$ret = array();
		foreach (array('trusted', 'internal', 'other', 'external') as $zone) {
			foreach (array('' => 4, '6' => 6) as $suffix => $version) {
				foreach ($this->readSetElements('nets-'.$zone.$suffix) as $network) {
					if ($this->validAddress($network, $version)) {
						$ret[$network] = $zone;
					}
				}
			}
		}
		return $ret;
	}

	public function addNetworkToZone($zone = false, $network = false, $cidr = false) {
		$this->ensureBaseRuleset();
		$element = $this->normalizeAddress($network, $cidr);
		$set = $this->setNameForZone($zone, $element);
		if ($set === false || $element === false) {
			return false;
		}
		return $this->addElement($set, $element);
	}

	public function removeNetworkFromZone($zone = false, $network = false, $cidr = false) {
		$element = $this->normalizeAddress($network, $cidr);
		$set = $this->setNameForZone($zone, $element);
		if ($set === false || $element === false) {
			return false;
		}
		return $this->deleteElement($set, $element, true);
	}

	public function changeNetworksZone($newzone = false, $network = false, $cidr = false) {
		foreach (array('trusted', 'internal', 'other', 'external') as $zone) {
			$this->removeNetworkFromZone($zone, $network, $cidr);
		}
		return $this->addNetworkToZone($newzone, $network, $cidr);
	}

	private function setNameForZone($zone, $network) {
		if (!in_array($zone, array('trusted', 'internal', 'other', 'external'), true)) {
			return false;
		}
		$host = explode('/', (string) $network, 2)[0];
		$v6 = filter_var($host, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV6);
		return 'nets-'.$zone.($v6 ? '6' : '');
	}

	public static function serviceChainName($service, $prefix = 'svc-') {
		$service = strtolower((string) $service);
		if (!preg_match('/^[a-z0-9][a-z0-9_-]{0,55}$/', $service)) {
			throw new \InvalidArgumentException('Invalid firewall service name');
		}
		return $prefix.$service;
	}

	public static function nftPortSpec($port) {
		$port = trim((string) $port);
		if (preg_match('/^(\d+)$/', $port, $match)) {
			$value = (int) $match[1];
			return ($value >= 1 && $value <= 65535) ? (string) $value : false;
		}
		if (preg_match('/^(\d+)[:\-](\d+)$/', $port, $match)) {
			$start = (int) $match[1];
			$end = (int) $match[2];
			return ($start >= 1 && $start <= $end && $end <= 65535)
				? $start.'-'.$end
				: false;
		}
		return false;
	}

	public function updateService($service = false, $ports = false) {
		$this->ensureBaseRuleset();
		$chain = self::serviceChainName($service);
		$this->ensureChain($chain);
		$script = 'flush chain '.self::FAMILY.' '.self::TABLE." $chain\n";
		if ($ports !== false && is_array($ports)) {
			foreach ($ports as $rule) {
				$protocol = isset($rule['protocol']) ? strtolower($rule['protocol']) : '';
				$port = isset($rule['port']) ? self::nftPortSpec($rule['port']) : false;
				if (!in_array($protocol, array('tcp', 'udp'), true) || $port === false) {
					continue;
				}
				$target = isset($rule['ratelimit']) ? 'jump fpbxratelimit' : 'accept';
				$script .= "add rule inet fpbx $chain $protocol dport $port $target\n";
			}
		}
		return $this->applyScript($script);
	}

	public function getActiveServices() {
		$output = array();
		$status = 0;
		$this->nftExec('list table '.self::FAMILY.' '.self::TABLE, $output, $status);
		if ($status !== 0) {
			return array();
		}
		$ret = array();
		if (preg_match_all('/^\s*chain svc-([a-z0-9_-]+)\s*\{/m', implode("\n", $output), $matches)) {
			foreach ($matches[1] as $service) {
				$ret[$service] = $service;
			}
		}
		return $ret;
	}

	public function removeService($service) {
		$chain = self::serviceChainName($service);
		unset($this->serviceZones[$service], $this->rejectServices[$service]);
		$this->rebuildZoneChains();
		$this->rebuildRejectChain();
		$output = array();
		$status = 0;
		$this->nftExec('delete chain '.self::FAMILY.' '.self::TABLE.' '.$chain, $output, $status);
		return $status === 0 || stripos(implode(' ', $output), 'No such file') !== false;
	}

	public function updateServiceZones($service = false, $zones = false) {
		self::serviceChainName($service);
		if (!isset($this->serviceZones[$service])) {
			$this->serviceZones[$service] = array();
		}
		if (is_array($zones)) {
			foreach ((array) ($zones['removefrom'] ?? array()) as $zone) {
				unset($this->serviceZones[$service][$zone]);
			}
			foreach ((array) ($zones['addto'] ?? array()) as $zone) {
				if ($this->validZone($zone)) {
					$this->serviceZones[$service][$zone] = true;
				}
			}
		}
		return $this->rebuildZoneChains();
	}

	private function rebuildZoneChains() {
		$script = '';
		foreach (array('trusted', 'internal', 'other', 'external') as $zone) {
			$script .= "flush chain inet fpbx zone-$zone\n";
			if ($zone === 'trusted') {
				$script .= "add rule inet fpbx zone-trusted accept\n";
				continue;
			}
			foreach ($this->serviceZones as $service => $zones) {
				if (!empty($zones[$zone])) {
					$script .= 'add rule inet fpbx zone-'.$zone.' jump '.self::serviceChainName($service)."\n";
				}
			}
		}
		return $this->applyScript($script);
	}

	public function changeInterfaceZone($iface = false, $newzone = false) {
		$this->ensureBaseRuleset();
		if (!preg_match('/^[a-zA-Z0-9_.:-]{1,15}$/', (string) $iface)) {
			return false;
		}
		unset($this->interfaceZones[$iface]);
		if ($newzone !== false && $newzone !== null && $newzone !== '') {
			if (!$this->validZone($newzone)) {
				return false;
			}
			$this->interfaceZones[$iface] = $newzone;
		}
		$script = "flush chain inet fpbx fpbxinterfaces\n";
		foreach ($this->interfaceZones as $interface => $zone) {
			$script .= 'add rule inet fpbx fpbxinterfaces iifname "'.$interface.'" jump zone-'.$zone."\n";
		}
		if (!$this->applyScript($script)) {
			return false;
		}
		return $this->syncInterfaceMasq();
	}

	private function syncInterfaceMasq() {
		$output = array();
		$status = 0;
		$this->nftExec('list table ip '.self::NAT_TABLE, $output, $status);
		if ($status !== 0) {
			if (!$this->applyScript("table ip ".self::NAT_TABLE." { chain postrouting { type nat hook postrouting priority srcnat; policy accept; } }\n")) {
				return false;
			}
		}
		$script = 'flush chain ip '.self::NAT_TABLE." postrouting\n";
		foreach ($this->interfaceZones as $interface => $zone) {
			if ($zone === 'external') {
				$script .= 'add rule ip '.self::NAT_TABLE.' postrouting oifname "'.$interface.'" masquerade'."\n";
			}
		}
		return $this->applyScript($script);
	}

	public function listInterfaceZones() {
		if ($this->interfaceZones) {
			return $this->interfaceZones;
		}
		$output = array();
		$status = 0;
		$this->nftExec('list chain inet fpbx fpbxinterfaces', $output, $status);
		if ($status === 0 && preg_match_all(
			'/iifname\s+"([^"]+)"\s+jump\s+zone-([a-z]+)/',
			implode("\n", $output),
			$matches,
			\PREG_SET_ORDER
		)) {
			foreach ($matches as $match) {
				$this->interfaceZones[$match[1]] = $match[2];
			}
		}
		return $this->interfaceZones;
	}

	public function setRtpPorts($rtp = false, $udptl = false) {
		$this->ensureBaseRuleset();
		$script = "flush chain inet fpbx fpbx-rtp\n";
		foreach (array($rtp, $udptl) as $range) {
			if (!is_array($range) || !isset($range['start'], $range['end'])) {
				continue;
			}
			$ports = self::nftPortSpec($range['start'].'-'.$range['end']);
			if ($ports !== false) {
				$script .= "add rule inet fpbx fpbx-rtp udp dport $ports accept\n";
			}
		}
		return $this->applyScript($script);
	}

	public static function rateSpec($seconds, $hitcount) {
		$seconds = max(1, (int) $seconds);
		$hitcount = max(1, (int) $hitcount);
		if ($seconds >= 86400 && $seconds % 86400 === 0) {
			return array(max(1, (int) ceil($hitcount / ($seconds / 86400))).'/day', $hitcount);
		}
		if ($seconds >= 60 && $seconds % 60 === 0) {
			return array(max(1, (int) ceil($hitcount / ($seconds / 60))).'/minute', $hitcount);
		}
		return array(max(1, (int) ceil($hitcount / $seconds)).'/second', $hitcount);
	}

	public function updateRFWtshld($rules) {
		if (!is_array($rules)) {
			throw new \InvalidArgumentException('Responsive Firewall rules must be an array');
		}
		$this->rfwRules = $rules;
		$script = "flush chain inet fpbx fpbxratelimit\n";
		$script .= "flush chain inet fpbx fpbxrfw\n";
		$script .= "add rule inet fpbx fpbxrfw ip saddr @rfw_whitelist accept\n";
		$script .= "add rule inet fpbx fpbxrfw ip6 saddr @rfw_whitelist6 accept\n";
		$script .= "add rule inet fpbx fpbxrfw ip saddr @rfw_tempwhitelist accept\n";
		$script .= "add rule inet fpbx fpbxrfw ip6 saddr @rfw_tempwhitelist6 accept\n";
		$script .= "add rule inet fpbx fpbxrfw ip saddr @rfw_attacker jump fpbxattacker\n";
		$script .= "add rule inet fpbx fpbxrfw ip6 saddr @rfw_attacker6 jump fpbxattacker\n";
		$script .= "add rule inet fpbx fpbxrfw ip saddr @rfw_clamped jump fpbxshortblock\n";
		$script .= "add rule inet fpbx fpbxrfw ip6 saddr @rfw_clamped6 jump fpbxshortblock\n";

		$tierMap = array(
			array('fpbxrfw', 'TIERA', 'rfw_tiera', 'rfw_attacker', 'fpbxattacker'),
			array('fpbxrfw', 'TIERB', 'rfw_tierb', 'rfw_clamped', 'fpbxshortblock'),
			array('fpbxrfw', 'TIERC', 'rfw_tierc', 'rfw_attacker', 'fpbxattacker'),
			array('fpbxratelimit', 'TIER3', 'rfw_rate3', 'rfw_attacker', 'fpbxattacker'),
			array('fpbxratelimit', 'TIER2', 'rfw_rate2', 'rfw_attacker', 'fpbxattacker'),
			array('fpbxratelimit', 'TIER1', 'rfw_rate1', 'rfw_clamped', 'fpbxshortblock'),
		);
		foreach ($tierMap as $tier) {
			list($group, $name, $meter, $set, $target) = $tier;
			if (!isset($rules[$group][$name]['seconds'], $rules[$group][$name]['hitcount'])) {
				continue;
			}
			list($rate, $burst) = self::rateSpec(
				$rules[$group][$name]['seconds'],
				$rules[$group][$name]['hitcount']
			);
			$timeout = max(1, (int) $rules[$group][$name]['seconds']).'s';
			$script .= "add rule inet fpbx $group meter $meter { ip saddr timeout $timeout limit rate over $rate burst $burst packets } add @$set { ip saddr timeout $timeout } jump $target\n";
			$script .= "add rule inet fpbx $group meter {$meter}6 { ip6 saddr timeout $timeout limit rate over $rate burst $burst packets } add @{$set}6 { ip6 saddr timeout $timeout } jump $target\n";
		}
		$script .= "add rule inet fpbx fpbxratelimit accept\n";
		return $this->applyScript($script);
	}

	public function updateTargets($rules) {
		$this->ensureBaseRuleset();
		$script = "flush chain inet fpbx fpbxsignalling\n";
		$signalling = $rules['smartports']['signalling'] ?? array();
		foreach ($signalling as $protocol => $entries) {
			if (!in_array($protocol, array('tcp', 'udp'), true)) {
				continue;
			}
			foreach ((array) $entries as $entry) {
				$port = $this->filterPort($entry);
				if ($port === false) {
					continue;
				}
				$responsive = !empty($rules['settings']['responsive'])
					&& !empty($rules['settings']['rprotocols'][$entry['name']]['state']);
				$mark = $responsive ? '0x3' : '0x1';
				$script .= "add rule inet fpbx fpbxsignalling $protocol dport $port meta mark set $mark\n";
			}
		}
		if (!$this->applyScript($script)) {
			return false;
		}
		$v4 = array();
		$v6 = array();
		foreach ((array) ($rules['smartports']['known'] ?? array()) as $address) {
			$normalized = $this->normalizeAddress($address);
			if ($normalized === false) {
				continue;
			}
			$host = explode('/', $normalized, 2)[0];
			if (filter_var($host, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV6)) {
				$v6[] = $normalized;
			} else {
				$v4[] = $normalized;
			}
		}
		return $this->replaceSet('smarthosts', $v4) && $this->replaceSet('smarthosts6', $v6);
	}

	private function filterPort($entry) {
		foreach (array('port', 'dport', 'dest') as $key) {
			if (isset($entry[$key]) && ($port = self::nftPortSpec($entry[$key])) !== false) {
				return $port;
			}
		}
		return false;
	}

	public function updateRegistrations($hosts) {
		$this->ensureBaseRuleset();
		$old = array_merge($this->readSetElements('registrations'), $this->readSetElements('registrations6'));
		$v4 = array();
		$v6 = array();
		foreach ((array) $hosts as $host) {
			$address = is_array($host) ? ($host['ip'] ?? reset($host)) : $host;
			if (filter_var($address, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV4)) {
				$v4[] = $address;
			} elseif (filter_var($address, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV6)) {
				$v6[] = $address;
			}
		}
		$this->replaceSet('registrations', $v4);
		$this->replaceSet('registrations6', $v6);
		$new = array_merge($v4, $v6);
		$ret = array();
		foreach (array_diff($new, $old) as $address) {
			$ret[$address] = 'ipadd';
		}
		foreach (array_diff($old, $new) as $address) {
			$ret[$address] = 'iprem';
		}
		return $ret;
	}

	public function updateBlacklist($blacklist) {
		$v4 = array();
		$v6 = array();
		foreach ((array) $blacklist as $entry => $resolved) {
			$items = ($resolved === false || !is_array($resolved))
				? array(is_numeric($entry) ? $resolved : $entry)
				: $resolved;
			foreach ($items as $address) {
				$normalized = $this->normalizeAddress($address);
				if ($normalized === false) {
					continue;
				}
				$host = explode('/', $normalized, 2)[0];
				if (filter_var($host, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV6)) {
					$v6[] = $normalized;
				} else {
					$v4[] = $normalized;
				}
			}
		}
		return $this->replaceSet('blacklist', $v4) && $this->replaceSet('blacklist6', $v6);
	}

	public function updateHostZones($hosts) {
		$this->hostZones = array();
		foreach ((array) $hosts as $address => $zone) {
			if ($this->normalizeAddress($address) !== false && $this->validZone($zone)) {
				$this->hostZones[$address] = $zone;
			}
		}
		$script = "flush chain inet fpbx fpbxhosts\n";
		foreach ($this->hostZones as $address => $zone) {
			$host = explode('/', $address, 2)[0];
			$family = filter_var($host, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV6) ? 'ip6' : 'ip';
			$script .= "add rule inet fpbx fpbxhosts $family saddr $address jump zone-$zone\n";
		}
		return $this->applyScript($script);
	}

	public function setRejectMode($drop = false, $log = false) {
		$script = "flush chain inet fpbx fpbxlogdrop\n";
		if ($log) {
			$script .= "add rule inet fpbx fpbxlogdrop log prefix \"fpbx-drop: \" flags all\n";
		}
		$script .= 'add rule inet fpbx fpbxlogdrop '.($drop ? 'drop' : 'reject')."\n";
		return $this->applyScript($script);
	}

	public function addToReject($name, $settings) {
		self::serviceChainName($name);
		$this->rejectServices[$name] = isset($settings['fw']) && is_array($settings['fw'])
			? $settings['fw']
			: array();
		return $this->rebuildRejectChain();
	}

	public function removeFromReject($name) {
		unset($this->rejectServices[$name]);
		return $this->rebuildRejectChain();
	}

	private function rebuildRejectChain() {
		$script = "flush chain inet fpbx fpbxreject\n";
		foreach ($this->rejectServices as $service => $rules) {
			foreach ($rules as $rule) {
				$protocol = isset($rule['protocol']) ? strtolower($rule['protocol']) : '';
				$port = isset($rule['port']) ? self::nftPortSpec($rule['port']) : false;
				if (in_array($protocol, array('tcp', 'udp'), true) && $port !== false) {
					$script .= "add rule inet fpbx fpbxreject $protocol dport $port jump fpbxlogdrop\n";
				}
			}
		}
		return $this->applyScript($script);
	}

	public function importCustomRules($file = '/etc/firewall.nft') {
		if (!is_file($file) || filesize($file) === 0) {
			return true;
		}
		$stat = @stat($file);
		if (!$stat || $stat['uid'] !== 0 || ($stat['mode'] & 0022)) {
			$this->l("$file must be root-owned and not group/world writable");
			return false;
		}
		$contents = file_get_contents($file);
		if ($contents === false || preg_match('/\b(flush\s+ruleset|delete\s+table)\b/i', $contents)) {
			$this->l("$file contains a destructive operation");
			return false;
		}
		if (!$this->applyScript($contents, true)) {
			return false;
		}
		return $this->applyScript($contents);
	}

	public function getZonesDetails() {
		$zones = array(
			'trusted' => array('networks' => array(), 'interfaces' => array()),
			'internal' => array('networks' => array(), 'interfaces' => array()),
			'other' => array('networks' => array(), 'interfaces' => array()),
			'external' => array('networks' => array(), 'interfaces' => array()),
		);
		foreach ($this->getKnownNetworks() as $network => $zone) {
			$zones[$zone]['networks'][] = $network;
		}
		foreach ($this->listInterfaceZones() as $interface => $zone) {
			$zones[$zone]['interfaces'][] = $interface;
		}
		return $zones;
	}

	public function &getCurrentIptables() {
		$interfaces = array();
		foreach ($this->listInterfaceZones() as $interface => $zone) {
			$interfaces[] = '-i '.$interface.' -j zone-'.$zone;
		}
		$this->cache = array(
			'ipv4' => array(
				'filter' => array('fpbxinterfaces' => $interfaces),
				'nat' => array(),
			),
			'ipv6' => array(
				'filter' => array('fpbxinterfaces' => $interfaces),
			),
		);
		return $this->cache;
	}

	public function addAttackAddress($set, $address, $timeout = 90) {
		if (!preg_match('/^rfw_(whitelist|attacker|clamped|tempwhitelist|discovered)$/', $set)) {
			return false;
		}
		$suffix = filter_var($address, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV6) ? '6' : '';
		$timeout = max(1, (int) $timeout);
		return $this->addElement($set.$suffix, $address.' timeout '.$timeout.'s');
	}

	public function removeAttackAddress($set, $address) {
		if (!preg_match('/^rfw_(whitelist|attacker|clamped|tempwhitelist|discovered)$/', $set)) {
			return false;
		}
		$suffix = filter_var($address, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV6) ? '6' : '';
		return $this->deleteElement($set.$suffix, $address, true);
	}

	private function ensureChain($chain) {
		$output = array();
		$status = 0;
		$this->nftExec('list chain inet fpbx '.$chain, $output, $status);
		if ($status === 0) {
			return true;
		}
		$this->nftExec('add chain inet fpbx '.$chain, $output, $status);
		return $status === 0;
	}

	private function replaceSet($set, $elements) {
		$script = "flush set inet fpbx $set\n";
		$elements = array_values(array_unique(array_filter($elements)));
		if ($elements) {
			$script .= "add element inet fpbx $set { ".implode(', ', $elements)." }\n";
		}
		return $this->applyScript($script);
	}

	private function addElement($set, $element) {
		if (!preg_match('/^[a-zA-Z0-9_-]+$/', $set)
			|| !preg_match('/^[0-9a-fA-F:.\/\-\s]+$/', $element)) {
			return false;
		}
		$output = array();
		$status = 0;
		$this->nftExec("add element inet fpbx $set { $element }", $output, $status);
		return $status === 0;
	}

	private function deleteElement($set, $element, $ignoreMissing = false) {
		if (!preg_match('/^[a-zA-Z0-9_-]+$/', $set)
			|| !preg_match('/^[0-9a-fA-F:.\/\-]+$/', $element)) {
			return false;
		}
		$output = array();
		$status = 0;
		$this->nftExec("delete element inet fpbx $set { $element }", $output, $status);
		return $status === 0 || $ignoreMissing;
	}

	private function readSetElements($set) {
		$output = array();
		$status = 0;
		$this->nftExec('list set inet fpbx '.$set, $output, $status);
		if ($status !== 0) {
			return array();
		}
		$blob = implode("\n", $output);
		if (!preg_match('/elements\s*=\s*\{([^}]*)\}/s', $blob, $match)) {
			return array();
		}
		$ret = array();
		foreach (explode(',', $match[1]) as $element) {
			$element = trim(preg_replace('/\s+(expires|timeout)\s+.*$/', '', trim($element)));
			if ($element !== '') {
				$ret[] = $element;
			}
		}
		return $ret;
	}

	private function normalizeAddress($address, $cidr = false) {
		if (!is_string($address) || $address === '') {
			return false;
		}
		if (strpos($address, '/') !== false) {
			list($address, $provided) = explode('/', $address, 2);
			if ($cidr === false || $cidr === null || $cidr === '') {
				$cidr = $provided;
			}
		}
		$v4 = filter_var($address, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV4);
		$v6 = filter_var($address, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV6);
		if (!$v4 && !$v6) {
			return false;
		}
		if ($cidr === false || $cidr === null || $cidr === '') {
			return $address;
		}
		$cidr = (int) $cidr;
		if (($v4 && ($cidr < 0 || $cidr > 32)) || ($v6 && ($cidr < 0 || $cidr > 128))) {
			return false;
		}
		return $address.'/'.$cidr;
	}

	private function validAddress($address, $version) {
		$host = explode('/', $address, 2)[0];
		$flag = $version === 6 ? \FILTER_FLAG_IPV6 : \FILTER_FLAG_IPV4;
		return filter_var($host, \FILTER_VALIDATE_IP, $flag) !== false;
	}

	private function validZone($zone) {
		return in_array($zone, array('trusted', 'internal', 'other', 'external'), true);
	}
}
