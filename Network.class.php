<?php
// vim: :set filetype=php tabstop=4 shiftwidth=4 autoindent smartindent:
namespace FreePBX\modules\Firewall;

class Network {

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
		if (!is_readable("/etc/sysconfig/network-scripts/ifcfg-$int")) {
			// No config
			$conf = array();
		} else {
			$conf = @parse_ini_file("/etc/sysconfig/network-scripts/ifcfg-$int", false, \INI_SCANNER_RAW);
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
		// SHMZ/CentOS/RHEL/etc - Update the zone in ifcfg-$iface
		$srcfile = "/etc/sysconfig/network-scripts/ifcfg-$iface";

		// If this is a tunnel interface, don't do anything
		if (strpos($iface, "tun") === 0) {
			return true;
		}

		// If newzone is false, something is wrong.
		if (!$newzone) {
			return true;
		}

		if (!file_exists($srcfile)) {
			// It doesn't exist. This is possibly because it's an alias,
			// and the BASE interface hasn't been configured.
			$out = "# Generic Firewall Configuration\n# Generated by FreeePBX Firewall.\n# This file MAY BE CHANGED by the end user\nZONE=trusted\n";
			file_put_contents($srcfile, $out);
			return;
		}
		if (is_link($srcfile)) {
			throw new \Exception("Symlink?");
		}

		// Grab the contents of the file
		$rawfile = file_get_contents($srcfile);
		$needsupdate = false;

		$ifcfg = @parse_ini_string($rawfile, false, \INI_SCANNER_RAW);

		// If it doesn't have a zone
		if (!isset($ifcfg['ZONE'])) {
			// Add it
			$rawfile .= "\nZONE=$newzone\n";
			$needsupdate = true;
		} else {
			if ($ifcfg['ZONE'] !== $newzone) {
				// Replace whatever it was
				$rawfile = preg_replace('/^ZONE.+$/m', "ZONE=$newzone", $rawfile);
				$needsupdate = true;
			}
		}

		if (!$descr) {
			$descr = "unset"; // Magic string
		}

		// Clean up descr by removing any EXISTING quotes, and passing it through
		// escapeshellcmd
		$descr = escapeshellcmd(str_replace(array('\'', '"'), "", $descr));

		if (!isset($ifcfg['DESCRIPTION'])) {
			$rawfile .= "\nDESCRIPTION=\"$descr\"\n";
			$needsupdate = true;
		} else {
			if ($ifcfg['DESCRIPTION'] !== $descr) {
				$rawfile = preg_replace('/^DESCRIPTION.+$/m', "DESCRIPTION=\"$descr\"", $rawfile);
				$needsupdate = true;
			}
		}

		// Do we need to update the file?
		if ($needsupdate) {
			// Remove any blank lines
			$clean = preg_replace('/\n+/m', "\n", $rawfile);
			file_put_contents($srcfile, $clean);
		}
		// Ensure permissions are sane
		chmod($srcfile, 0755);
	}
}

