<?php
// vim: :set filetype=php tabstop=4 shiftwidth=4 autoindent smartindent:
namespace FreePBX\modules\Firewall;

class Network {

	public function discoverInterfaces() {
		exec("/sbin/ip -o addr", $result, $ret);
		if ($ret != 0) {
			throw new \Exception('ip -o addr failed somehow.');
		}

		$interfaces = array();

		foreach ($result as $line) {
			$vals = preg_split("/\s+/", $line);

			if ($vals[1] == "lo" || $vals[1] == "lo:") 
				continue;

			// We only care about ipv4 (inet) and ipv6 (inet6) lines, or definition lines
			if ($vals[2] != "inet" && $vals[2] != "inet6" && $vals[3] != "mtu")
				continue;

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
				$intname = $vals[1];
			}

			// Strip netmask off the end of the IP address
			$ret = preg_match("/(.+)\/(\d*+)/", $vals[3], $ip);

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
			$conf = @parse_ini_file("/etc/sysconfig/network-scripts/ifcfg-$int");
		}

		// Is it a VLAN? 
		if (strpos($int, ".") !== false) {
			$intarr = explode(".", $conf['DEVICE']);
			if (!isset($int[1])) {
				throw new \Exception("VLAN Defined, but interface wrong - ".$conf['DEVICE']);
			}
			list($vlanid) = explode(":", $intarr[1]);
			$conf['VLANID'] = $vlanid;
			$conf['VLAN'] = true;
		}

		// If this is an alias (has a colon) then we can't use it as
		// a parent interface. 
		if (strpos($int, ":") !== false) {
			$conf['PARENT'] = false;
		} else {
			$conf['PARENT'] = true;
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
}
