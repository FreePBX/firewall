<?php
// vim: :set filetype=php tabstop=4 shiftwidth=4 autoindent smartindent:
namespace FreePBX\modules\Firewall;

class Network {
	
	CONST INTERFACE_ZONES_CONFIG = '/var/spool/asterisk/firewall/interface-zones.json';

	public function discoverInterfaces() {
		exec("/sbin/ip -o addr", $result, $ret);
		if ($ret != 0) {
			throw new \Exception('ip -o addr failed somehow.');
		}

		return $this->parseIpOutput($result);
	}

	public function parseIpOutput($result) {

		$interfaces = array();

		foreach ($result as $line) {
			$vals = preg_split("/\s+/", $line);

			if ($vals[1] == "lo" || $vals[1] == "lo:") 
				continue;

			// Skip sangoma wanpipe cards, which appear as network interfaces
			 if (preg_match("/^w\d*g\d*/", $vals[1])) {
				continue;
			}

			// We only care about ipv4 (inet) and ipv6 (inet6) lines, or definition lines
			if ($vals[2] != "inet" && $vals[2] != "inet6" && $vals[3] != "mtu") {
				continue;
			}

			// FREEPBX-17657 - OpenVZ produces lines like this: 
			//    "2: venet0    inet 127.0.0.1/32 scope host venet0"
			// which are useless. They don't have an 8th param, so we can just skip them

			if (!isset($vals[8])) {
				continue;
			}

			if (preg_match("/(.+?)(?:@.+)?:$/", $vals[1], $res)) { // Matches vlans, which are eth0.100@eth0
				// It's a network definition.
				// This won't clobber an exsiting one, as it always comes
				// before the IP addresses.
				$interfaces[$res[1]] = array("addresses" => array(), "config" => array());
				continue;
			}

			// Is this a named secondary?
			if ($vals[8] == "secondary") {
				// I shall call him sqishy and he shall be mine, and he
				// shall be my squishy.
				if (isset($vals[9])) {
					$intname = $vals[9];
					if (!isset($interfaces[$intname])) {
						$interfaces[$intname] = array("addresses" => array(), "config" => array());
					}
				} else {
					// Whatevs. I don't care. Fine. Be unnamed.
					$intname = $vals[1];
				}
			} else {
				if ($vals[7] == "global") {
					// FREEPBX-13396 - This may be 'dynamic', not ACTUALLY the real name.
					if ($vals[8] === "dynamic" || $vals[8] === "noprefixroute") {
						$intname = $vals[9];
					} else {
						$intname = $vals[8];
					}
				} else {
					$intname = $vals[1];
				}
			}

			// It's possible for intname to end with a trailing backslash
			$intname = str_replace("\\", "", $intname);

			// Strip netmask off the end of the IP address
			if (!preg_match("/(.+)\/(\d*+)/", $vals[3], $ip)) {
				// This is probably a point to point interface. Set it to be /32
				$ip = array($vals[3]."/32", $vals[3], "32");
			}

			// Is this an IPv6 link-local address? Don't display it if it is.
			if ($ip[1][0] == "f" && $ip[1][1] == "e") {
				continue;
			}
			$interfaces[$intname]['addresses'][] = array($ip[1], $intname, $ip[2]);
		}
		// OK, now get the configuration for all the interfaces.
		$ints = array_keys($interfaces);

		if ($ints === false) {
			throw new \Exception("No Interfaces? Naaaah");
		}

		foreach ($ints as $i) {
			$interfaces[$i]['config'] = $this->getInterfaceConfig($i);
			// Is this a tunnel interface? Alway Internal. No matter what.
			if (strpos($i, "tun") === 0) {
				$interfaces[$i]['config']['ZONE'] = "internal";
			}
		}
		return $interfaces;
	}

	public function getInterfaceConfig($int) {
		// TODO: Portable-ize this.
		return $this->getRedhatInterfaceConfig($int);
	}

	public function getRedhatInterfaceConfig($int) {
		// No config
		$conf = $this->getInterfaceZoneData($int);
		if (is_readable("/etc/network/interfaces.d/$int")) {
			$fileContent = file_get_contents("/etc/network/interfaces.d/$int");
			$lines = explode("\n", $fileContent);

			$onBoot = 'no';
			foreach ($lines as $line) {
				if (trim($line) == "auto $int") {
					$onBoot = 'yes';
				} else if (strpos($line, "iface $int") !== false) {
					$data = explode(' ', trim($line));
					if (in_array($data[3], ['static', 'dhcp', 'none'])) {
						$protocol = $data[3];

						$conf['ONBOOT'] = $onBoot;
						$conf['NAME'] = "$int";
						$conf['DEVICE'] = "$int";
						$conf['BOOTPROTO'] = $protocol;
					}
				} else if (strpos($line, "gateway") !== false) {
					$data = explode(' ', trim($line));
					if ($conf['BOOTPROTO'] == 'static') {
						$conf['GATEWAY'] = $data[1];
					}
				}
			}
		}

		// Is it a VLAN? 
		if (strpos($int, ".") !== false) {
			$intarr = explode(".", $int);
			list($vlanid) = explode(":", $intarr[1]);
			$conf['VLANID'] = $vlanid;
			$conf['VLAN'] = true;
		}

		// If this is an alias (has a colon) then it has a parent interface. 
		if (strpos($int, ":") !== false) {
			$parent = explode(":", $int);
			$conf['PARENT'] = $parent[0];
		} else {
			$conf['PARENT'] = false;
		}

		// 'DESCRIPTION=unset' is a magic 'not set' string.
		if (isset($conf['DESCRIPTION']) && $conf['DESCRIPTION'] === "unset") {
			unset ($conf['DESCRIPTION']);
		}

		return $conf;
	}

	public function getDefault() {
		// returns interface the default route is on
		exec("/sbin/route -n", $result, $ret);
		if ($ret != 0) 
			throw new \Exception('Unable to run route');

		$int = "";
		$router = "";
		foreach ($result as $line) {
			$exploded = preg_split('/\s+/', $line);
			if ($exploded[0] == "0.0.0.0") {
				$int = $exploded[7];
				$router = $exploded[1];
			}
		}
		return array("interface" => $int, "router" => $router);
	}

	public function updateInterfaceZone($iface, $newzone = false, $descr = false) {
		// If this is a tunnel interface, don't do anything
		if (strpos($iface, "tun") === 0) {
			return true;
		}

		// If newzone is false, something is wrong.
		if (!$newzone) {
			return true;
		}

		if (!$descr) {
			$descr = "unset"; // Magic string
		}

		// Clean up descr by removing any EXISTING quotes, and passing it through
		// escapeshellcmd
		$descr = escapeshellcmd(str_replace(array('\'', '"'), "", $descr));

		$data = [
			'ZONE' => $newzone,
			'DESCRIPTION' => $descr
		];
		$this->updateInterfaceZoneData($iface, $data);
	}

	public function getAllInterfaceZoneData() {
		if (!file_exists(self::INTERFACE_ZONES_CONFIG)) {
			return [];
		}

		$data = file_get_contents(self::INTERFACE_ZONES_CONFIG);
		if (!$data) {
			return [];
		}

		return json_decode($data, true);
	}

	public function getInterfaceZoneData($interface) {
		$interfaceZoneData = $this->getAllInterfaceZoneData();
		if (!isset($interfaceZoneData[$interface])) {
			return [
				'ZONE' => 'external',
				'DESCRIPTION' => 'unset'
			];
		}

		return $interfaceZoneData[$interface];
	}

	public function updateInterfaceZoneData($interface, $data) {
		if (!file_exists(self::INTERFACE_ZONES_CONFIG)) {
			return false;
		}
		$interfaceZoneData = $this->getAllInterfaceZoneData();
		$interfaceZoneData[$interface] = $data;
		$config = self::INTERFACE_ZONES_CONFIG;
		if (is_link($config) || is_link(dirname($config))) {
			return false;
		}
		$temporary = $config.'.tmp';
		if (is_link($temporary) || file_put_contents($temporary, json_encode($interfaceZoneData)) === false) {
			return false;
		}
		if (!rename($temporary, $config)) {
			@unlink($temporary);
			return false;
		}
		return true;
	}
}

